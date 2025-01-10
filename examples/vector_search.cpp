// the system assumes 3 parties - client, search engine, and content provider
// we can easily implement the other configurations also using cofhe library
// the content provider will calculate the encrypted embeddings vecotrs using the specified model and network encryption key
// then content provider will send this encrypted vectors to the search engine
// when a client wants to search for a query, the client will encrypt generate a embedding vector for the query and send the encrypted query vector to the search engine
// now search engine will use OpenVector network to calculate the distance between the query vector and the content vectors and send the ids of the top k closest vectors to the client
// now the client can request the content provider to get the actual content of the top k vectors
// using this we achieve seperation of concerns and provide privacy to the client, the search engine will not know the actual content of the vectors and cannot use the vectors for any other purpose then searching
// the content provider will not know the query and just we need the content
// in this setting the search engine will know the id but we assume that there are sufficient access controls to prevent the search engine from accessing the content
// if this is not the  case we can easily implement other version, such as making the cosine_distance function return a ciphertext and not float
// and then the search engine can compare the ciphertexts and return the ids of the top k vectors(current comparision method will reveal the actual distance between the vectors)

#include <iostream>
#include <chrono>
#include <random>
#include <functional>
#include <unordered_map>
#include <inttypes.h>

#include "cofhe.hpp"

using namespace CoFHE;
using CryptoSystem = CPUCryptoSystem;
using PlainText = CryptoSystem::PlainText;
using CipherText = CryptoSystem::CipherText;

float cosine_distance(ClientNode<CryptoSystem> &client_node, const Tensor<CipherText *> &a, const Tensor<CipherText *> &b, float a_mag, float b_mag)
{
    if (a.ndim() != 1 || b.ndim() != 1 || a.shape()[0] != b.shape()[0])
    {
        throw std::runtime_error("Invalid input tensors");
    }
    auto &cs = client_node.crypto_system();
    auto &pk = client_node.network_public_key();
    ComputeRequest req_mul(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::BINARY, ComputeRequest::ComputeOperation::MULTIPLY, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(a)), ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::TENSOR, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext_tensor(b))}));
    ComputeResponse *res_mul;
    client_node.compute(req_mul, &res_mul);
    if (res_mul->status() != ComputeResponse::Status::OK)
    {
        throw std::runtime_error("Failed to compute dot product");
    }
    auto dot_product = cs.deserialize_ciphertext_tensor(res_mul->data());
    dot_product.flatten();
    auto dot_product_sum = *dot_product.at(0);
    for (size_t i = 1; i < dot_product.num_elements(); i++)
    {
        dot_product_sum = cs.add_ciphertexts(pk, dot_product_sum, *dot_product.at(i));
    }
    ComputeRequest req_dot_product(ComputeRequest::ComputeOperationInstance(ComputeRequest::ComputeOperationType::UNARY, ComputeRequest::ComputeOperation::DECRYPT, {ComputeRequest::ComputeOperationOperand(ComputeRequest::DataType::SINGLE, ComputeRequest::DataEncrytionType::CIPHERTEXT, cs.serialize_ciphertext(dot_product_sum))}));
    ComputeResponse *res_dot_product;
    client_node.compute(req_dot_product, &res_dot_product);
    if (res_dot_product->status() != ComputeResponse::Status::OK)
    {
        throw std::runtime_error("Failed to compute dot product");
    }
    auto dot_product_val = cs.get_float_from_plaintext(cs.deserialize_plaintext(res_dot_product->data()));
    auto distance = 1 - dot_product_val / (float)(a_mag * b_mag);
    delete res_mul;
    delete res_dot_product;
    return distance;
}

class VectorDB
{
public:
    VectorDB(ClientNode<CryptoSystem> &client_node) : client_node_m(client_node) {}

    void insert(uint64_t id, const Tensor<CipherText *> &vec, float mag)
    {
        // Use emplace to avoid default construction
        db_.emplace(id, std::make_pair(mag, vec));
    }

    void insert(const std::vector<std::pair<uint64_t, std::pair<float, Tensor<CipherText *>>>> &vecs)
    {
        for (const auto &vec : vecs)
        {
            db_.emplace(vec.first, vec.second); // Avoid operator[] for insertion
        }
    }

    void topk(std::vector<size_t> &res, const Tensor<CipherText *> &query, float query_mag, size_t k, std::function<float(ClientNode<CryptoSystem> &, const Tensor<CipherText *> &, const Tensor<CipherText *> &, float, float)> distance)
    {
        std::vector<std::pair<size_t, float>> dists;

        for (const auto &vec : db_)
        {
            float dist = distance(client_node_m, query, vec.second.second, query_mag, vec.second.first);
            dists.emplace_back(vec.first, dist);
        }

        std::sort(dists.begin(), dists.end(), [](const std::pair<size_t, float> &a, const std::pair<size_t, float> &b)
                  { return a.second < b.second; });

        res.clear();
        for (size_t i = 0; i < k && i < dists.size(); i++)
        {
            res.push_back(dists[i].first);
        }
    }

private:
    ClientNode<CryptoSystem> &client_node_m;
    std::unordered_map<uint64_t, std::pair<float, Tensor<CipherText *>>> db_;
};

std::vector<uint64_t> generate_embeddings(const std::string &model, const std::pair<uint64_t, std::string> &content,bool query=false)
{
    std::vector<uint64_t> embeddings(5, 0);
    auto content_str = content.second;
    std::transform(content.second.begin(), content.second.end(), content_str.begin(), [](unsigned char c)
                   { return std::tolower(c); });
    // generate embeddings using the model, for demo we just generate embeddings based on certain words
    // we have dmodel as 5 and each word represents a dimension
    // first dimension represents word "paris"
    // second dimension represents word "tiger"
    // third dimension represents word "ai"
    // fourth dimension represents word "missile"
    // fifth dimension represents word "cryptocurrency"
    if (content_str.find("paris") != std::string::npos)
    {
        embeddings[0] = 1;
    }
    else if (content_str.find("tiger") != std::string::npos)
    {
        embeddings[1] = 1;
    }
    else if (content_str.find("ai") != std::string::npos)
    {
        embeddings[2] = 1;
    }
    else if (content_str.find("missile") != std::string::npos)
    {
        embeddings[3] = 1;
    }
    else if (content_str.find("cryptocurrency") != std::string::npos)
    {
        embeddings[4] = 1;
    }
    return embeddings;
}

float get_magnitude(std::vector<uint64_t> &embeddings)
{
    float mag = 0;
    for (const auto &emb : embeddings)
    {
        mag += emb * emb;
    }
    return std::sqrt(mag);
}

class ContentProvider
{
public:
    ContentProvider() : content_(get_content()) {}

    std::string get_content(uint64_t id)
    {
        return content_[id];
    }

    std::vector<std::pair<uint64_t, std::pair<float, Tensor<CipherText *>>>> get_encrypted_embeddings(ClientNode<CryptoSystem> &client_node)
    {
        auto embeddings = get_embeddings();
        std::vector<std::pair<uint64_t, std::pair<float, Tensor<CipherText *>>>> encrypted_embeddings;
        auto &cs = client_node.crypto_system();
        auto &pk = client_node.network_public_key();
        for (const auto &emb : embeddings)
        {
            Tensor<CipherText *> enc_emb(emb.second.second.size(), nullptr);
            enc_emb.flatten();
            for (size_t i = 0; i < emb.second.second.size(); i++)
            {
                enc_emb.at(i) = new CipherText(cs.encrypt(pk, cs.make_plaintext(emb.second.second[i])));
            }
            encrypted_embeddings.push_back({emb.first, {emb.second.first, enc_emb}});
        }
        return encrypted_embeddings;
    }

private:
    std::vector<std::string> content_;

    std::vector<std::pair<uint64_t, std::pair<uint64_t, std::vector<uint64_t>>>> get_embeddings()
    {
        std::vector<std::pair<uint64_t, std::pair<uint64_t, std::vector<uint64_t>>>> embeddings;
        auto content = get_content();
        for (size_t i = 0; i < content.size(); i++)
        {
            auto emb = generate_embeddings("model", {0, content[i]});
            embeddings.push_back({i, {get_magnitude(emb), emb}});
        }
        return embeddings;
    }

    std::vector<std::string> get_content()
    {
        std::vector<std::string> content;
        content.push_back("Paris is the capital of France");
        content.push_back("Tiger is the national animal of India");
        content.push_back("AI is the future");
        content.push_back("Missile is a weapon");
        content.push_back("Cryptocurrency is the future of money");
        return content;
    }
};

class SearchEngine
{
public:
    SearchEngine(VectorDB &db) : db_m(db) {}

    void register_content_data(const std::vector<std::pair<uint64_t, std::pair<float, Tensor<CipherText *>>>> &vecs)
    {
        db_m.insert(vecs);
    }

    void search(std::vector<size_t> &res, const Tensor<CipherText *> &query, float query_mag, size_t k)
    {
        db_m.topk(res, query,query_mag, k , cosine_distance);
    }

private:
    VectorDB &db_m;
};

class Client
{
public:
    Client(ClientNode<CryptoSystem> &client_node, SearchEngine &search_engine, ContentProvider &content_provider) : client_node_m(client_node), search_engine_m(search_engine), content_provider_m(content_provider) {}

    std::string search(const std::string &query, size_t k)
    {
        auto embeddings = generate_embeddings("model", {0, query});
        auto embeddings_mag = get_magnitude(embeddings);
        auto &cs = client_node_m.crypto_system();
        auto &pk = client_node_m.network_public_key();
        Tensor<CipherText *> query_vec(embeddings.size(), nullptr);
        query_vec.flatten();
        for (size_t i = 0; i < embeddings.size(); i++)
        {
            query_vec.at(i) = new CipherText(cs.encrypt(pk, cs.make_plaintext(embeddings[i])));
        }

        std::vector<uint64_t> res;
        search_engine_m.search(res, query_vec, embeddings_mag, k);
        std::string result;
        for (const auto &id : res)
        {
            if (result.size() > 0)
            {
                result += "\n";
            }
            result += content_provider_m.get_content(id);
        }
        return result;
    }

private:
    ClientNode<CryptoSystem> &client_node_m;
    SearchEngine &search_engine_m;
    ContentProvider &content_provider_m;
};

int main(int argc, char **argv)
{
    if (argc < 6)
    {
        std::cerr << "Usage: " << argv[0] << " <client_ip> <client_port> <setup_ip> <setup_port> <query>" << std::endl;
        return 1;
    }

    auto self_details = NodeDetails{argv[1], argv[2], NodeType::CLIENT_NODE};
    auto setup_node_details = NodeDetails{argv[3], argv[4], NodeType::SETUP_NODE};
    auto client_node = make_client_node<CryptoSystem>(setup_node_details);
    auto &cs = client_node.crypto_system();
    auto &pk = client_node.network_public_key();

    auto db = VectorDB(client_node);
    auto content_provider = ContentProvider();
    auto search_engine = SearchEngine(db);
    auto client = Client(client_node, search_engine, content_provider);

    search_engine.register_content_data(content_provider.get_encrypted_embeddings(client_node));

    std::string query = argv[5];

    auto result = client.search(query, 1);
    std::cout << "Search result for query: " << query << std::endl;
    std::cout << result << std::endl;
    return 0;
}

// ./vector_search 127.0.0.1 35455 127.0.0.1  4455 'Tell me about Paris'