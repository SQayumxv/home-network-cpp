#include "http_server.hpp"
#include "httplib.h"
#include "../dns/dns_service.hpp"
#include "../platform/network_platform.hpp"
#include <fstream>
#include <thread>

namespace home {
void serve_http(Application& app,int port,const std::filesystem::path& web,std::stop_token stop) {
    httplib::Server server;
    server.new_task_queue=[] {return new httplib::ThreadPool(4,32);};
    server.set_payload_max_length(128*1024);server.set_read_timeout(2,0);server.set_write_timeout(2,0);server.set_keep_alive_max_count(10);
    const std::string host="127.0.0.1:"+std::to_string(port),origin="http://"+host;
    server.set_pre_routing_handler([&](const httplib::Request& req,httplib::Response& res){
        bool bad=req.get_header_value("Host")!=host;
        if(req.has_header("Origin") && req.get_header_value("Origin")!=origin)bad=true;
        if(req.has_header("Sec-Fetch-Site") && req.get_header_value("Sec-Fetch-Site")=="cross-site")bad=true;
        if(req.method=="POST" && (req.get_header_value("X-Home-Prototype")!="1" || req.get_header_value("Content-Type").find("application/json")!=0))bad=true;
        if(bad){res.status=403;res.set_content("Forbidden","text/plain");return httplib::Server::HandlerResponse::Handled;}
        return httplib::Server::HandlerResponse::Unhandled;
    });
    server.set_post_routing_handler([](const httplib::Request&,httplib::Response& res){res.set_header("Cache-Control","no-store");res.set_header("X-Content-Type-Options","nosniff");res.set_header("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'");});
    auto json=[](httplib::Response& res,const Json& value){res.set_content(value.dump(),"application/json");};
    auto handler=[json](auto function){return [function,json](const httplib::Request& req,httplib::Response& res){try{json(res,function(req));}catch(const std::exception& error){res.status=400;json(res,{{"error",error.what()}});}};};
    server.Get("/api/status",handler([&](const auto&){return app.snapshot();}));
    server.Get("/api/config",handler([&](const auto&){return app.config();}));
    server.Get("/api/traffic",handler([&](const auto& req){return app.traffic(req.get_param_value("id"),req.get_param_value("range")=="day");}));
    for(const std::string operation:{"preview","apply","confirm","rollback"})server.Post("/api/config/"+operation,handler([&,operation](const auto& req){return app.change(operation,Json::parse(req.body));}));
    server.Post("/api/simulation/connection",handler([&](const auto& req){return app.connection(Json::parse(req.body));}));
    server.Post("/api/simulation/scenario",handler([&](const auto& req){return app.scenario(Json::parse(req.body));}));
    server.Post("/api/dns/test",handler([&](const auto& req){auto input=Json::parse(req.body);auto start=std::chrono::steady_clock::now();auto upstream=dns_servers();if(upstream.size()>2)upstream.resize(2);auto answer=dns_result(dns_response(dns_query(input.at("name").template get<std::string>()),app.dns_settings(),upstream));answer["elapsed_ms"]=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();return answer;}));
    server.Get("/",[&](const auto&,auto& res){std::ifstream input(web/"index.html",std::ios::binary);if(!input){res.status=500;res.set_content("Dashboard assets not found. Run from the project directory or set --web.","text/plain");return;}std::string data((std::istreambuf_iterator<char>(input)),{});res.set_content(data,"text/html");});
    for(const auto* filename:{"app.js","styles.css"})server.Get(std::string("/")+filename,[&,filename](const auto&,auto& res){std::ifstream input(web/filename,std::ios::binary);if(!input){res.status=404;return;}std::string data((std::istreambuf_iterator<char>(input)),{});res.set_content(data,std::string(filename).ends_with(".js")?"application/javascript":"text/css");});
    if(!server.bind_to_port("127.0.0.1",port))throw std::runtime_error("Dashboard port unavailable");
    std::jthread closer([&](std::stop_token own){while(!stop.stop_requested() && !own.stop_requested())std::this_thread::sleep_for(std::chrono::milliseconds(100));server.stop();});
    server.listen_after_bind();
}
}
