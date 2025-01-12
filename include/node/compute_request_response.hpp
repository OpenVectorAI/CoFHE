#ifndef CoFHE_COMPUTE_REQUEST_RESPONSE_HPP_INCLUDED
#define CoFHE_COMPUTE_REQUEST_RESPONSE_HPP_INCLUDED

#include <string>
#include <vector>
#include <sstream>

namespace CoFHE
{
    class ComputeResponse
    {
    public:
        enum class Status
        {
            OK,
            ERROR,
        };

        ComputeResponse(Status status, std::string data) : status_m(status), data_m(data) {}

        Status &status() { return status_m; }
        const Status &status() const { return status_m; }
        std::string &data() { return data_m; }
        const std::string &data() const { return data_m; }

        std::string to_string() const
        {
            return std::to_string(static_cast<int>(status_m)) + " " + std::to_string(data_m.size()) + "\n" + data_m;
        }

        static ComputeResponse from_string(const std::string &str)
        {
            std::istringstream iss(str);
            std::string line;
            std::getline(iss, line);
            std::istringstream iss_line(line);
            int status;
            size_t data_size;
            iss_line >> status >> data_size;
            std::string data = str.substr(line.size() + 1);
            if (data.size() != data_size)
            {
                throw std::runtime_error("Data size mismatch");
            }
            return ComputeResponse(static_cast<Status>(status), data);
        }

    private:
        Status status_m;
        std::string data_m;
    };

    class ComputeRequest
    {
    public:
        using ResponseType = ComputeResponse;
        enum class ComputeOperationType
        {
            UNARY,
            BINARY,
            TERNARY,
        };
        enum class ComputeOperation
        {
            DECRYPT,
            ADD,
            SUBTRACT,
            MULTIPLY,
            DIVIDE,
            // POLYNOMIAL_EVALUATION,
            // SMPC
        };

        enum class DataType
        {
            SINGLE,
            TENSOR,
            TENSOR_ID, // data encryption type will be ignored if tensor id is used
        };

        enum class DataEncrytionType
        {
            PLAINTEXT,
            CIPHERTEXT,
        };

        class ComputeOperationOperand
        {
        public:
            ComputeOperationOperand(DataType data_type, DataEncrytionType encryption_type, std::string data) : data_type_m(data_type), encryption_type_m(encryption_type), data_m(data) {}

            DataType &data_type() { return data_type_m; }
            const DataType &data_type() const { return data_type_m; }
            DataEncrytionType &encryption_type() { return encryption_type_m; }
            const DataEncrytionType &encryption_type() const { return encryption_type_m; }
            std::string &data() { return data_m; }
            const std::string &data() const { return data_m; }

            std::string to_string() const
            {
                return std::to_string(static_cast<int>(data_type_m)) + " " + std::to_string(static_cast<int>(encryption_type_m)) + " " + std::to_string(data_m.size()) + "\n" + data_m + "\n";
            }

            static ComputeOperationOperand from_string(const std::string &str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int data_type, encryption_type;
                size_t data_size;
                iss >> data_type >> encryption_type >> data_size;
                std::string data = str.substr(line.size() + 1, data_size);
                if (data.size() != data_size)
                {
                    throw std::runtime_error("Data size mismatch");
                }
                return ComputeOperationOperand(static_cast<DataType>(data_type), static_cast<DataEncrytionType>(encryption_type), data);
            }

            static std::vector<ComputeOperationOperand> from_string(const std::string &str, size_t num_operands)
            {
                std::istringstream iss(str);
                std::vector<ComputeOperationOperand> operands;
                for (size_t i = 0; i < num_operands; i++)
                {
                    std::string operand_str_1;
                    std::getline(iss, operand_str_1);
                    iss >> std::ws;
                    int data_type, encryption_type;
                    size_t data_size;
                    std::istringstream iss_line(operand_str_1);
                    iss_line >> data_type >> encryption_type >> data_size;
                    // get the next data_size chars
                    std::string data = str.substr(iss.tellg(), data_size);
                    iss.seekg(data_size, std::ios_base::cur);
                    iss >> std::ws;
                    operands.push_back(ComputeOperationOperand(static_cast<DataType>(data_type), static_cast<DataEncrytionType>(encryption_type), data));
                }
                return operands;
            };

        private:
            DataType data_type_m;
            DataEncrytionType encryption_type_m;
            std::string data_m;
        };

        class ComputeOperationInstance
        {
        public:
            ComputeOperationInstance(const ComputeOperationType &operation_type,
                                     const ComputeOperation &operation,
                                     const std::vector<ComputeOperationOperand> &operands) : operation_type_m(operation_type), operation_m(operation),
                                                                                             operands_m(operands) {}

            ComputeOperationType &operation_type() { return operation_type_m; }
            const ComputeOperationType &operation_type() const { return operation_type_m; }
            ComputeOperation &operation() { return operation_m; }
            const ComputeOperation &operation() const { return operation_m; }
            std::vector<ComputeOperationOperand> &operands() { return operands_m; }
            const std::vector<ComputeOperationOperand> &operands() const { return operands_m; }

            std::string to_string() const
            {
                std::string str = std::to_string(static_cast<int>(operation_type_m)) + " " + std::to_string(static_cast<int>(operation_m)) + " " +
                                  std::to_string(operands_m.size()) + "\n";
                for (const auto &operand : operands_m)
                {
                    str += operand.to_string();
                }
                return str;
            }

            static ComputeOperationInstance from_string(const std::string &str)
            {
                std::istringstream iss(str);
                std::string line;
                std::getline(iss, line);
                std::istringstream iss_line(line);
                int operation_type, operation;
                size_t num_operands;
                iss_line >> operation_type >> operation >> num_operands;
                std::string operands_str = str.substr(line.size() + 1);
                std::vector<ComputeOperationOperand> operands = ComputeOperationOperand::from_string(operands_str, num_operands);
                return ComputeOperationInstance(static_cast<ComputeOperationType>(operation_type), static_cast<ComputeOperation>(operation), operands);
            }

        private:
            ComputeOperationType operation_type_m;
            ComputeOperation operation_m;
            std::vector<ComputeOperationOperand> operands_m;
        };

        ComputeRequest(const ComputeOperationInstance &operation) : operation_m(operation) {}

        ComputeOperationInstance &operation() { return operation_m; }
        const ComputeOperationInstance &operation() const { return operation_m; }

        std::string to_string() const
        {
            return operation_m.to_string();
        }

        static ComputeRequest from_string(const std::string &str)
        {
            ComputeOperationInstance operation = ComputeOperationInstance::from_string(str);
            return ComputeRequest(operation);
        }

    private:
        ComputeOperationInstance operation_m;
    };
}
#endif // CoFHE_COMPUTE_REQUEST_RESPONSE_HPP_INCLUDED