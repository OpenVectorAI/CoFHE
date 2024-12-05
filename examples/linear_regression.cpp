#include <iostream>
#include <memory>
#include <string>
#include <chrono>

#include "cofhe.hpp"
#include "node/network_details.hpp"
#include "node/client_node.hpp"
#include "node/compute_request_handler.hpp"

using namespace CoFHE;
using CryptoSystem = CoFHE::CPUCryptoSystem;
using CipherText = CryptoSystem::CipherText;
using PlainText = CryptoSystem::PlainText;
using CipherTextTensor = Tensor<CryptoSystem::CipherText *>;
using PlainTextTensor = Tensor<CryptoSystem::PlainText *>;

void print_plaintext_tensor(CryptoSystem &cs, PlainTextTensor &tensor)
{
    auto shape = tensor.shape();
    tensor.flatten();
    for (size_t i = 0; i < tensor.num_elements(); i++)
    {
        std::cout << cs.get_float_from_plaintext(*tensor.at(i)) << " ";
    }
    std::cout << std::endl;
    tensor.reshape(shape);
}

CryptoSystem::CipherText compute_cost(
    ClientNode<CoFHE::CPUCryptoSystem> &client_node, const CipherTextTensor &y, const CipherTextTensor &y_hat)
{
    size_t num_samples = y_hat.shape()[0];
    auto &cs = client_node.crypto_system();
    auto &pk = client_node.network_public_key();
    auto negate_y = cs.negate_ciphertext_tensor(pk, y);
    auto add_y_hat_y_negate = cs.add_ciphertext_tensors(pk, y_hat, negate_y);
    add_y_hat_y_negate.flatten();
    auto ser = cs.serialize_ciphertext_tensor(add_y_hat_y_negate);
    ComputeRequest req(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, ser), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, ser)}));
    ComputeResponse *res;
    client_node.compute(req, &res);
    if (res->status() != ComputeResponse::Status::OK)
    {
        throw std::runtime_error("Failed to compute cost");
    }
    auto cost_tensor = cs.deserialize_ciphertext_tensor(res->data());
    auto cost = *cost_tensor.at(0);
    for (size_t i = 1; i < cost_tensor.num_elements(); i++)
    {
        cost = cs.add_ciphertexts(pk, cost, *cost_tensor.at(i));
    }
    delete res;
    negate_y.flatten();
    add_y_hat_y_negate.flatten();
    for (size_t i = 0; i < cost_tensor.num_elements(); i++)
    {
        delete cost_tensor.at(i);
        delete negate_y.at(i);
        delete add_y_hat_y_negate.at(i);
    }
    return cost;
}

CipherTextTensor predict(ClientNode<CoFHE::CPUCryptoSystem> &client_node, const CipherTextTensor &X, PlainTextTensor &weights, const CipherTextTensor &bias)
{
    auto &cs = client_node.crypto_system();
    auto &pk = client_node.network_public_key();
    auto scal_weights = cs.scal_ciphertext_tensors(pk, weights, X);
    auto scal_weights_bias = cs.add_ciphertext_tensors(pk, scal_weights, bias);
    scal_weights.flatten();
    for (size_t i = 0; i < scal_weights.num_elements(); i++)
    {
        delete scal_weights.at(i);
    }
    return scal_weights_bias;
}

void update_params(ClientNode<CoFHE::CPUCryptoSystem> &client_node, const CipherTextTensor &x, const CipherTextTensor &y, const CipherTextTensor &y_hat, PlainTextTensor &weights, CipherTextTensor &bias_, float learning_rate)
{
    auto &cs = client_node.crypto_system();
    auto &pk = client_node.network_public_key();
    auto y_negation = cs.negate_ciphertext_tensor(pk, y);
    auto y_hat_minus_y = cs.add_ciphertext_tensors(pk, y_hat, y_negation);

    size_t num_samples = y_hat.shape()[0];
    size_t num_features = x.shape()[1];

    // update bias
    bias_.flatten();
    y_hat_minus_y.flatten();
    auto bias = *bias_.at(0);
    auto sum_y_hat_minus_y = *y_hat_minus_y.at(0);
    for (size_t i = 1; i < num_samples; i++)
    {
        sum_y_hat_minus_y = cs.add_ciphertexts(pk, sum_y_hat_minus_y, *y_hat_minus_y.at(i));
    }
    y_hat_minus_y.reshape({num_samples, 1});
    ComputeRequest req_bias(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext(sum_y_hat_minus_y))}));
    ComputeResponse *res_bias;
    client_node.compute(req_bias, &res_bias);
    if (res_bias->status() != ComputeResponse::Status::OK)
    {
        throw std::runtime_error("Failed to compute gradient");
    }
    ComputeRequest req_bias_curr(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext(bias))}));
    ComputeResponse *res_bias_curr;
    client_node.compute(req_bias_curr, &res_bias_curr);
    if (res_bias_curr->status() != ComputeResponse::Status::OK)
    {
        throw std::runtime_error("Failed to compute gradient");
    }
    auto bias_curr = cs.get_float_from_plaintext(cs.deserialize_plaintext(res_bias_curr->data()));
    auto y_hat_minus_y_sum = cs.get_float_from_plaintext(cs.deserialize_plaintext(res_bias->data()));
    auto new_bias_ = cs.make_plaintext(bias_curr - y_hat_minus_y_sum * learning_rate / num_samples);
    auto new_bias = cs.encrypt(pk, new_bias_);
    delete res_bias;
    delete res_bias_curr;
    for (size_t i = 0; i < num_samples; i++)
    {
        delete bias_.at(i);
        bias_.at(i) = new CipherText(new_bias);
    }
    bias_.reshape({num_samples, 1});

    // update weights
    Tensor<CipherText *> x_t({num_features, num_samples}, nullptr);
    x_t.flatten();
    auto x_flatten = x;
    x_flatten.flatten();
    for (size_t i = 0; i < num_samples; i++)
    {
        for (size_t j = 0; j < num_features; j++)
        {
            x_t.at(j * num_samples + i) = x_flatten.at(i * num_features + j);
        }
    }
    x_t.reshape({num_features, num_samples});
    ComputeRequest req(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(x_t)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(y_hat_minus_y))}));
    ComputeResponse *res;
    client_node.compute(req, &res);
    if (res->status() != ComputeResponse::Status::OK)
    {
        throw std::runtime_error("Failed to compute gradient");
    }
    ComputeRequest req_dec(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, res->data())}));
    ComputeResponse *res_dec;
    client_node.compute(req_dec, &res_dec);
    if (res_dec->status() != ComputeResponse::Status::OK)
    {
        throw std::runtime_error("Failed to compute gradient");
    }
    auto y_hat_minus_y_x = cs.deserialize_plaintext_tensor(res_dec->data());
    y_hat_minus_y_x.flatten();
    std::vector<float> scal_y_hat_minus_y_x_v;
    for (size_t i = 0; i < y_hat_minus_y_x.num_elements(); i++)
    {
        scal_y_hat_minus_y_x_v.push_back(cs.get_float_from_plaintext(*y_hat_minus_y_x.at(i)) * learning_rate / num_samples);
    }
    std::vector<float> new_weights_v;
    weights.flatten();
    for (size_t i = 0; i < weights.num_elements(); i++)
    {
        new_weights_v.push_back(cs.get_float_from_plaintext(*weights.at(i)) - scal_y_hat_minus_y_x_v[i]);
    }
    PlainTextTensor new_weights(num_features, 1, nullptr);
    new_weights.flatten();
    for (size_t i = 0; i < num_features; i++)
    {
        new_weights.at(i) = new PlainText(cs.make_plaintext(new_weights_v[i]));
    }
    new_weights.reshape({num_features, 1});
    delete res;
    delete res_dec;
    weights.flatten();
    new_weights.flatten();
    y_negation.flatten();
    y_hat_minus_y.flatten();
    y_hat_minus_y_x.flatten();
    for (size_t i = 0; i < y_hat_minus_y_x.num_elements(); i++)
    {
        delete y_negation.at(i);
        delete y_hat_minus_y.at(i);
        delete y_hat_minus_y_x.at(i);
        delete weights.at(i);
        weights.at(i) = new_weights.at(i);
    }
    weights.reshape({num_features, 1});
}

class DataSet
{
public:
    DataSet(ClientNode<CoFHE::CPUCryptoSystem> &client_node, const std::vector<std::vector<float>> &X, const std::vector<float> &y) : X_m(X), y_m(y), num_features_m(X_m[0].size()), num_samples_m(X_m.size()), encrypted_X_m(num_samples_m, num_features_m, nullptr), encrypted_y_m(num_samples_m, 1, nullptr)
    {
        if (X_m.size() != y_m.size())
        {
            throw std::runtime_error("Invalid dataset");
        }
        encrypt_X(client_node);
        encrypt_y(client_node);
    }

    const CipherTextTensor &encrypted_X() const { return encrypted_X_m; }
    const CipherTextTensor &encrypted_y() const { return encrypted_y_m; }

    static DataSet read_csv(const std::string &file_path, ClientNode<CoFHE::CPUCryptoSystem> &client_node)
    {
        std::ifstream file(file_path);
        if (!file.is_open())
        {
            throw std::runtime_error("Failed to open file");
        }
        std::vector<std::vector<float>> X;
        std::vector<float> y;
        std::string line;
        std::getline(file, line);
        while (std::getline(file, line))
        {
            std::vector<float> row;
            std::stringstream ss(line);
            std::string cell;
            while (std::getline(ss, cell, ','))
            {
                row.push_back(std::stof(cell));
            }
            y.push_back(row.back());
            row.pop_back();
            X.push_back(row);
        }
        return DataSet(client_node, X, y);
    }

private:
    std::vector<std::vector<float>> X_m;
    std::vector<float> y_m;
    size_t num_features_m;
    size_t num_samples_m;
    CipherTextTensor encrypted_X_m;
    CipherTextTensor encrypted_y_m;

    void encrypt_X(ClientNode<CoFHE::CPUCryptoSystem> &client_node)
    {
        auto &cs = client_node.crypto_system();
        auto &pk = client_node.network_public_key();
        PlainTextTensor pt_X(num_samples_m, num_features_m, nullptr);
        pt_X.flatten();
        for (size_t i = 0; i < num_samples_m; i++)
        {
            for (size_t j = 0; j < num_features_m; j++)
            {
                pt_X.at(i * num_features_m + j) = new PlainText(cs.make_plaintext(X_m[i][j]));
            }
        }
        encrypted_X_m = cs.encrypt_tensor(pk, pt_X);
        encrypted_X_m.reshape({num_samples_m, num_features_m});
        for (size_t i = 0; i < num_samples_m; i++)
        {
            for (size_t j = 0; j < num_features_m; j++)
            {
                delete pt_X.at(i * num_features_m + j);
            }
        }
    }

    void encrypt_y(ClientNode<CoFHE::CPUCryptoSystem> &client_node)
    {
        auto &cs = client_node.crypto_system();
        auto &pk = client_node.network_public_key();
        PlainTextTensor pt_y(num_samples_m, nullptr);
        pt_y.flatten();
        for (size_t i = 0; i < num_samples_m; i++)
        {
            pt_y.at(i) = new PlainText(cs.make_plaintext(y_m[i]));
        }
        encrypted_y_m = cs.encrypt_tensor(pk, pt_y);
        encrypted_y_m.reshape({num_samples_m, 1});
        for (size_t i = 0; i < num_samples_m; i++)
        {
            delete pt_y.at(i);
        }
    }
};

class LinearRegression
{
public:
    LinearRegression(ClientNode<CoFHE::CPUCryptoSystem> &client_node, const DataSet &data_set, float learning_rate = 0.01) : client_node_m(client_node), data_set_m(data_set), num_features_m(data_set.encrypted_X().shape()[1]), num_samples_m(data_set.encrypted_X().shape()[0]), weights_m(num_features_m, 1, nullptr), bias_m(num_samples_m, 1, nullptr), learning_rate_m(learning_rate)
    {
        auto &cs = client_node.crypto_system();
        auto &pk = client_node.network_public_key();
        weights_m.flatten();
        for (size_t i = 0; i < num_features_m; i++)
        {
            weights_m.at(i) = new PlainText(cs.make_plaintext(0));
        }
        weights_m.reshape({num_features_m, 1});
        auto enc_bias = cs.encrypt(pk, cs.make_plaintext(0));
        bias_m.flatten();
        for (size_t i = 0; i < data_set.encrypted_X().shape()[0]; i++)
        {
            bias_m.at(i) = new CipherText(enc_bias);
        }
        bias_m.reshape({num_samples_m, 1});
    }

    ~LinearRegression()
    {
        weights_m.flatten();
        bias_m.flatten();
        for (size_t i = 0; i < weights_m.num_elements(); i++)
        {
            delete weights_m.at(i);
        }
        for (size_t i = 0; i < bias_m.num_elements(); i++)
        {
            delete bias_m.at(i);
        }
    }

    void train(size_t epochs)
    {
        for (size_t i = 0; i < epochs; i++)
        {
            auto y_hat = predict(client_node_m, data_set_m.encrypted_X(), weights_m, bias_m);
            auto cost = compute_cost(client_node_m, data_set_m.encrypted_y(), y_hat);
            ComputeRequest req_cost(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node_m.crypto_system().serialize_ciphertext(cost))}));
            ComputeResponse *res_cost;
            client_node_m.compute(req_cost, &res_cost);
            if (res_cost->status() != ComputeResponse::Status::OK)
            {
                throw std::runtime_error("Failed to compute cost");
            }
            auto cost_val = client_node_m.crypto_system().get_float_from_plaintext(client_node_m.crypto_system().deserialize_plaintext(res_cost->data()));
            cost_val /= 2 * num_samples_m;
            std::cout << "Epoch: " << i << " Cost: " << cost_val << std::endl;
            update_params(client_node_m, data_set_m.encrypted_X(), data_set_m.encrypted_y(), y_hat, weights_m, bias_m, learning_rate_m);
        }
    }

    void test()
    {
        auto y_hat = predict(client_node_m, data_set_m.encrypted_X(), weights_m, bias_m);
        ComputeRequest req_dec_y(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node_m.crypto_system().serialize_ciphertext_tensor(data_set_m.encrypted_y()))}));
        ComputeResponse *res_dec_y;
        client_node_m.compute(req_dec_y, &res_dec_y);
        if (res_dec_y->status() != ComputeResponse::Status::OK)
        {
            throw std::runtime_error("Failed to decrypt y");
        }
        auto y_val = client_node_m.crypto_system().deserialize_plaintext_tensor(res_dec_y->data());
        std::cout << "Actual: ";
        y_val.flatten();
        for (size_t i = 0; i < y_val.num_elements(); i++)
        {
            std::cout << client_node_m.crypto_system().get_float_from_plaintext(*y_val.at(i)) << " ";
            delete y_val.at(i);
        }
        std::cout << std::endl;
        ComputeRequest req_dec_y_hat(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node_m.crypto_system().serialize_ciphertext_tensor(y_hat))}));
        ComputeResponse *res_dec_y_hat;
        client_node_m.compute(req_dec_y_hat, &res_dec_y_hat);
        if (res_dec_y_hat->status() != ComputeResponse::Status::OK)
        {
            throw std::runtime_error("Failed to decrypt y_hat");
        }
        auto y_hat_val = client_node_m.crypto_system().deserialize_plaintext_tensor(res_dec_y_hat->data());
        std::cout << "Predicted: ";
        y_hat_val.flatten();
        for (size_t i = 0; i < y_hat_val.num_elements(); i++)
        {
            std::cout << client_node_m.crypto_system().get_float_from_plaintext(*y_hat_val.at(i)) << " ";
            delete y_hat_val.at(i);
        }
        std::cout << std::endl;
        auto cost = compute_cost(client_node_m, data_set_m.encrypted_y(), y_hat);
        ComputeRequest req(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node_m.crypto_system().serialize_ciphertext(cost))}));
        ComputeResponse *res;
        client_node_m.compute(req, &res);
        if (res->status() != ComputeResponse::Status::OK)
        {
            throw std::runtime_error("Failed to compute cost");
        }
        auto cost_val = client_node_m.crypto_system().get_float_from_plaintext(client_node_m.crypto_system().deserialize_plaintext(res->data()));
        cost_val /= 2 * num_samples_m;
        std::cout << "Cost: " << cost_val << std::endl;
        std::cout << "Trained weights: ";
        print_plaintext_tensor(client_node_m.crypto_system(), weights_m);
        std::cout << "Trained bias: ";
        ComputeRequest req_dec_bias(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::CIPHERTEXT, client_node_m.crypto_system().serialize_ciphertext(*bias_m.at(0, 0)))}));
        ComputeResponse *res_dec_bias;
        client_node_m.compute(req_dec_bias, &res_dec_bias);
        if (res_dec_bias->status() != ComputeResponse::Status::OK)
        {
            throw std::runtime_error("Failed to decrypt bias");
        }
        auto bias_val = client_node_m.crypto_system().get_float_from_plaintext(client_node_m.crypto_system().deserialize_plaintext(res_dec_bias->data()));
        std::cout << bias_val << std::endl;
        delete res;
        delete res_dec_y;
        delete res_dec_y_hat;
        delete res_dec_bias;
    }

    void set_weights(const std::vector<float> &weights)
    {
        if (weights.size() != num_features_m)
        {
            throw std::runtime_error("Invalid weights");
        }
        auto &cs = client_node_m.crypto_system();
        for (size_t i = 0; i < num_features_m; i++)
        {
            weights_m.at(i) = new PlainText(cs.make_plaintext(weights[i]));
        }
    }

    void set_bias(float bias)
    {
        auto &cs = client_node_m.crypto_system();
        auto &pk = client_node_m.network_public_key();
        auto enc_bias = cs.encrypt(pk, cs.make_plaintext(bias));
        for (size_t i = 0; i < num_samples_m; i++)
        {
            bias_m.at(i) = new CipherText(enc_bias);
        }
    }

private:
    ClientNode<CoFHE::CPUCryptoSystem> &client_node_m;
    size_t num_features_m;
    size_t num_samples_m;
    const DataSet &data_set_m;
    PlainTextTensor weights_m;
    CipherTextTensor bias_m;
    float learning_rate_m;
};

int main(int argc, char *argv[])
{
    if (argc != 8)
    {
        std::cerr << "Usage: " << argv[0] << "self_node_ip self_node_port setup_node_ip setup_node_port dataset_path num_epochs learning_rate" << std::endl;
        return 1;
    }
    auto self_details = NodeDetails{argv[1], argv[2], NodeType::CLIENT_NODE};
    auto setup_node_details = NodeDetails{argv[3], argv[4], NodeType::SETUP_NODE};
    auto client_node = make_client_node<CPUCryptoSystem>(setup_node_details);
    const std::string file_path(argv[5]);
    int num_epochs = std::stoi(argv[6]);
    float learning_rate = std::stof(argv[7]);
    auto data_set = DataSet::read_csv(file_path, client_node);
    auto lr = LinearRegression(client_node, data_set, learning_rate);
    auto start = std::chrono::high_resolution_clock::now();
    lr.train(num_epochs);
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "Time taken: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << "ms" << std::endl;
    lr.test();
    return 0;
}