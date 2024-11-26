#ifndef CoFHE_NODE_ROOT_REQUEST_HANDLER_HPP_INCLUDED
#define CoFHE_NODE_ROOT_REQUEST_HANDLER_HPP_INCLUDED

#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <vector>

#include "node/request_response.hpp"
#include "node/compute_request_handler.hpp"
#include "node/cofhe_node_request_handler.hpp"
#include "node/setup_node_request_handler.hpp"


namespace CoFHE
{
    namespace Network
    {
        template <typename Handler, typename Request, typename Response>
        concept RequestHandlerConcept = requires(Handler h, Request r) {
            typename Handler::RequestType;
            requires RequestType<typename Handler::RequestType>;
            { h.handle_request(r) }
              -> std::same_as<Response>;
        };

        template <typename Handler, typename RequestImpl, typename ResponseImpl>
            requires RequestHandlerConcept<Handler, RequestImpl, ResponseImpl>
        class RequestHandler
        {
        public:
            RequestHandler(Handler &handler) : handler_m(handler) {}

            Response handle_request(Request req)
            {
                if constexpr (std::is_same_v<RequestImpl, ComputeRequest>)
                {
                    if (req.type() == ServiceType::COMPUTE_REQUEST)
                    {
                        return Response(req.protocol_version(), req.type(), Response::Status::OK, handler_m.handle_request(ComputeRequest::from_string(req.data())).to_string());
                    }
                }
                else if constexpr (std::is_same_v<RequestImpl, CoFHENodeRequest>)
                {
                    if (req.type() == ServiceType::COFHE_REQUEST)
                    {
                        return Response(req.protocol_version(), req.type(), Response::Status::OK, handler_m.handle_request(CoFHENodeRequest::from_string(req.data())).to_string());
                    }
                }
                else if constexpr (std::is_same_v<RequestImpl, SetupNodeRequest>)
                {
                    if (req.type() == ServiceType::SETUP_REQUEST)
                    {
                        return Response(req.protocol_version(), req.type(), Response::Status::OK, handler_m.handle_request(SetupNodeRequest::from_string(req.data())).to_string());
                    }
                }
                return Response(req.protocol_version(), req.type(), Response::Status::ERROR, "Invalid request type");
            }

        private:
            Handler &handler_m;
        };
    } // namespace Network
} // namespace CoFHE
#endif