#ifndef CoFHE_NODE_SERVER_HPP_INCLUDED
#define CoFHE_NODE_SERVER_HPP_INCLUDED

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/ssl.hpp>

#include "node/request_response.hpp"
#include "node/root_request_handler.hpp"

#define SERVER_THREAD_COUNT 8

namespace CoFHE
{
    namespace Network
    {

        namespace asio = boost::asio;
        namespace ssl = boost::asio::ssl;
        using tcp = boost::asio::ip::tcp;

        template <typename RequestHandlerImpl, typename RequestImpl, typename ResponseImpl>
        class Session : public std::enable_shared_from_this<Session<RequestHandlerImpl, RequestImpl, ResponseImpl>>
        {
        public:
            Session(asio::ssl::stream<tcp::socket> socket, RequestHandlerImpl &handler) : socket_m(std::move(socket)), handler_m(handler) {}

            Session(const Session &) = delete;
            Session &operator=(const Session &) = delete;
            Session(Session &&) = default;
            Session &operator=(Session &&) = default;
            ~Session() = default;

            void start()
            {
                do_handshake();
            }

        private:
            using std::enable_shared_from_this<Session<RequestHandlerImpl, RequestImpl, ResponseImpl>>::shared_from_this;
            asio::ssl::stream<tcp::socket> socket_m;
            RequestHandler<RequestHandlerImpl, RequestImpl, ResponseImpl> handler_m;
            std::string read_buffer;
            std::string write_buffer;


            void do_handshake()
            {
                auto self(shared_from_this());
                socket_m.async_handshake(asio::ssl::stream_base::server, [this, self](const std::error_code &error)
                                         {
                    if(!error){
                        do_read();
                    } });
            }

            void do_read()
            {
                auto self(shared_from_this());
                asio::async_read_until(socket_m, asio::dynamic_buffer(read_buffer), '\n', [this, self](const std::error_code &error, size_t bytes_transferred)
                                       {
                    if(!error){
                        try{
                            // the data can contain more data than the header specifies
                            // so in next call read the remaining data
                            auto header_str = read_buffer.substr(0, bytes_transferred);
                            std::cout<<header_str<<std::endl;
                            if (read_buffer.size() > bytes_transferred)
                            {
                                read_buffer = read_buffer.substr(bytes_transferred);
                            }
                            else
                            {
                                read_buffer.clear();
                            }
                            auto header = Request::RequestHeader::from_string(header_str);
                            if (header.data_size() > read_buffer.size())
                            {
                            asio::async_read(socket_m, asio::dynamic_buffer(read_buffer),
                            asio::transfer_exactly(header.data_size()- read_buffer.size()), [this, self, header](const std::error_code &error, size_t bytes_transferred){
                                if(!error){
                                    process_request(header, read_buffer);
                                } else{
                                    std::cerr << "Read failed: " << error.message() << std::endl;
                                    end_session();
                                }
                            });
                            }
                            else{
                                process_request(header, read_buffer);
                            }
                        }
                        catch(const std::exception &e){
                            std::cerr << "Error: " << e.what() << std::endl;
                            end_session();
                        }
                    }
                    else{
                        std::cerr << "Read failed: " << error.message() << std::endl;
                        end_session();
                    } });
            }

            void process_request(Request::RequestHeader header, std::string &data)
            {
                try
                {
                    auto req = Request::from_string(header, data.substr(0, header.data_size()));
                    data.erase(0, header.data_size());
                    auto res = handler_m.handle_request(req);
                    write_buffer = res.to_string();
                    do_write();
                }
                catch (const std::exception &e)
                {
                    std::cerr << "Error: " << e.what() << std::endl;
                    end_session();
                }
            }

            void do_write()
            {
                auto self(shared_from_this());
                asio::async_write(socket_m, asio::buffer(write_buffer,write_buffer.size()), [this, self](const std::error_code &error, size_t bytes_transferred)
                                  {
                    if (!error)
                    {
                        do_read();
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

        template <typename RequestHandlerImpl, typename Request, typename Response>
        class Server
        {
        public:
            Server(const std::string &address, const std::string &port, RequestHandlerImpl &&handler, size_t thread_pool_size = SERVER_THREAD_COUNT) : thread_pool_size_m(thread_pool_size), acceptor_m(io_context_m), context_m(asio::ssl::context::sslv23), request_handler_m(std::move(handler)), signals_m(io_context_m, SIGINT, SIGTERM)
            {
                signals_m.add(SIGINT);
                signals_m.add(SIGTERM);
                do_await_stop();
                context_m.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 | asio::ssl::context::single_dh_use);
                // context_m.set_verify_mode(asio::ssl::verify_peer);
                context_m.set_verify_mode(asio::ssl::verify_none);
                context_m.use_certificate_chain_file("./server.pem");
                context_m.use_private_key_file("./server_key.pem", asio::ssl::context::pem);
                // context_m.use_tmp_dh_file("./dh512.pem");
                asio::ip::tcp::resolver resolver(io_context_m);
                asio::ip::tcp::endpoint endpoint = *resolver.resolve(address, port).begin();
                acceptor_m.open(endpoint.protocol());
                acceptor_m.set_option(asio::ip::tcp::acceptor::reuse_address(true));
                acceptor_m.bind(endpoint);
                acceptor_m.listen();
                do_accept();
            }

            Server(const Server &) = delete;
            Server &operator=(const Server &) = delete;
            Server(Server &&) = default;
            Server &operator=(Server &&) = default;
            ~Server() = default;

            void run()
            {
                std::vector<std::shared_ptr<std::thread>> threads;
                for (size_t i = 0; i < thread_pool_size_m; ++i)
                {
                    threads.push_back(std::make_shared<std::thread>([this]()
                                                                    { io_context_m.run(); }));
                }
                for (size_t i = 0; i < threads.size(); ++i)
                {
                    threads[i]->join();
                }
            }

        private:
            size_t thread_pool_size_m;
            asio::io_context io_context_m;
            asio::ip::tcp::acceptor acceptor_m;
            asio::ssl::context context_m;
            RequestHandlerImpl request_handler_m;
            asio::signal_set signals_m;

            void do_accept()
            {
                acceptor_m.async_accept([this](const std::error_code &error, asio::ip::tcp::socket socket)
                                        {
                    if (!error)
                    {
                        std::make_shared<Session<RequestHandlerImpl,Request,Response>>(boost::asio::ssl::stream<tcp::socket>(std::move(socket), context_m),request_handler_m
                        )->start();
                    }
                    do_accept(); });
            }

            void do_await_stop()
            {
                signals_m.async_wait(
                    [this](boost::system::error_code e, int signal)
                    {
                        io_context_m.stop();
                    });
            }
        };
    } // namespace Network
} // namespace CoFHE
#endif