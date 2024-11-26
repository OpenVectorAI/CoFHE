#ifndef CoFHE_NODE_CLIENT_HPP_INCLUDED
#define CoFHE_NODE_CLIENT_HPP_INCLUDED

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/ssl.hpp>

#include "node/request_response.hpp"

namespace CoFHE
{
    namespace Network
    {

        namespace asio = boost::asio;
        namespace ssl = boost::asio::ssl;
        using tcp = boost::asio::ip::tcp;

        class Client
        {
        public:
            Client(const std::string &address, const std::string &port, bool keep_session_alive = false) : io_context_m(), context_m(asio::ssl::context::sslv23), socket_m(io_context_m, context_m), keep_session_alive_m(keep_session_alive)
            {
                context_m.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 | asio::ssl::context::single_dh_use);
                // context_m.set_verify_mode(asio::ssl::verify_peer);
                context_m.set_verify_mode(asio::ssl::verify_none);
                context_m.load_verify_file("./server.pem");
                asio::ip::tcp::resolver resolver(io_context_m);
                asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(address, port);
                asio::connect(socket_m.lowest_layer(), endpoints);
                // socket_m.set_verify_mode(asio::ssl::verify_peer);
                socket_m.set_verify_callback(asio::ssl::rfc2818_verification(address));
                socket_m.handshake(asio::ssl::stream_base::client);
            }

            Client(const Client &) = delete;
            Client &operator=(const Client &) = delete;
            Client(Client &&) = default;
            Client &operator=(Client &&) = default;
            ~Client() = default;

            template <typename T>
                requires RequestType<T> && ResponseType<typename T::ResponseType>
            void run(ServiceType type, const T &r, typename T::ResponseType **res)
            {

                if (io_context_m.stopped())
                {
                    io_context_m.restart();
                    read_buffer.clear();
                }
                auto req = Request(ProtocolVersion::V1, type, r.to_string());
                write_buffer = req.to_string();
                do_write(res);
                io_context_m.run();
            }

            void close()
            {
                end_session();
            }

            bool is_session_alive()
            {
                return keep_session_alive_m;
            }

            void set_session_alive(bool keep_session_alive)
            {
                keep_session_alive_m = keep_session_alive;
            }

        private:
            asio::io_context io_context_m;
            asio::ssl::context context_m;
            asio::ssl::stream<asio::ip::tcp::socket> socket_m;
            bool keep_session_alive_m;
            std::string read_buffer;
            std::string write_buffer;

            template <typename T>
                requires ResponseType<T>
            void do_read(T **res)
            {
                asio::async_read_until(socket_m, asio::dynamic_buffer(read_buffer), '\n', [this, res](const std::error_code &error, size_t bytes_transferred)
                                       {
                    if (!error)
                    {
                        try
                        {
                            auto res_header_str = read_buffer.substr(0, bytes_transferred);
                            if (read_buffer.size() > bytes_transferred)
                            {
                                read_buffer = read_buffer.erase(0, bytes_transferred);
                            }
                            else
                            {
                                read_buffer.clear();
                            }
                            auto res_header = Response::ResponseHeader::from_string(res_header_str);
                            if (res_header.data_size()>read_buffer.size())
                            {
                            asio::async_read(socket_m, asio::dynamic_buffer(read_buffer), asio::transfer_exactly(res_header.data_size()-read_buffer.size()), [this, res_header, res](const std::error_code &error, size_t bytes_transferred)
                                             {
                                if (!error)
                                {   
                                    process_request(res_header, read_buffer, res);
                                }
                                else
                                {
                                    std::cerr << "Read failed: " << error.message() << std::endl;
                                    end_session();
                                }
                            });
                            }
                            else{
                                process_request(res_header, read_buffer, res);
                            }
                        }
                        catch(const std::exception &e){
                            std::cerr << "Error: " << e.what() << std::endl;
                            end_session();
                        }
                    }
                    else
                    {
                        std::cerr << "Read failed: " << error.message() << std::endl;
                        end_session();
                    } });
            }

            template <typename T>
                requires ResponseType<T>
            void process_request(const Response::ResponseHeader &header, std::string &data, T **res)
            {
                try
                {
                    *res = new T(T::from_string(read_buffer.substr(0, header.data_size())));
                    if (!keep_session_alive_m)
                    {
                        end_session();
                    }
                    data.erase(0, header.data_size());
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error: " << e.what() << std::endl;
                    end_session();
                }
            }

            template <typename T>
                requires ResponseType<T>
            void do_write(T **res)
            {
                asio::async_write(socket_m, asio::buffer(write_buffer, write_buffer.size()), [this, res](const std::error_code &error, size_t bytes_transferred)
                                  {
                    if (!error)
                    {
                        do_read(res);
                    }
                    else
                    {
                        std::cerr << "Write failed: " << error.message() << std::endl;
                        end_session();
                    } });
            }
            void end_session()
            {
                try
                {
                    socket_m.shutdown();
                    socket_m.lowest_layer().close();
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error closing session: " << e.what() << std::endl;
                }
            }
        };

        auto make_client(const std::string &address, const std::string &port, bool keep_session_alive = false)
        {
            return Client(address, port, keep_session_alive);
        }

    } // namespace Network
} // namespace CoFHE
#endif