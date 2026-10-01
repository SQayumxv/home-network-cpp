#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "dns_service.hpp"
#include "../platform/network_platform.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <stdexcept>

namespace home {
namespace {
struct Socket {
    SOCKET value{INVALID_SOCKET};
    explicit Socket(SOCKET s) : value(s) {}
    ~Socket() { if(value!=INVALID_SOCKET) closesocket(value); }
    Socket(const Socket&)=delete; Socket& operator=(const Socket&)=delete;
};
unsigned word(const DnsPacket& p, size_t i) { return (unsigned(p.at(i))<<8)|p.at(i+1); }
void put(DnsPacket& p, unsigned value) { p.push_back(static_cast<unsigned char>(value>>8)); p.push_back(static_cast<unsigned char>(value)); }
bool matches(const std::string& name,const Json& list) {
    for(const auto& entry:list) { auto s=entry.get<std::string>(); if(name==s || (name.size()>s.size() && name.ends_with("."+s))) return true; } return false;
}
bool question(const DnsPacket& p,std::string& name,size_t& end) {
    if(p.size()<12 || (p[2]&0xf8)!=0 || word(p,4)!=1) return false;
    size_t at=12;
    while(at<p.size() && p[at]) {
        unsigned size=p[at++]; if(size>63 || at+size>p.size()) return false;
        if(!name.empty()) name+='.';
        for(unsigned i=0;i<size;++i) { unsigned char ch=p[at++]; if(ch<33 || ch>126) return false; name+=static_cast<char>(std::tolower(ch)); }
        if(name.size()>253) return false;
    }
    if(at>=p.size() || name.empty() || at+5>p.size()) return false;
    end=at+5; return true;
}
DnsPacket error_response(const DnsPacket& q,unsigned code,size_t end=0) {
    DnsPacket p(12,0); if(q.size()>=2) {p[0]=q[0];p[1]=q[1];}
    p[2]=0x80 | (q.size()>2 ? q[2]&1 : 0); p[3]=static_cast<unsigned char>(0x80|code);
    if(end) {p[5]=1;p.insert(p.end(),q.begin()+12,q.begin()+end);} return p;
}
bool ready(SOCKET s,int millis) { fd_set r{};FD_ZERO(&r);FD_SET(s,&r);timeval t{millis/1000,(millis%1000)*1000};return select(0,&r,nullptr,nullptr,&t)>0; }
bool receive_exact(SOCKET s,char* p,int count) { while(count) {int got=recv(s,p,count,0);if(got<=0)return false;p+=got;count-=got;}return true; }
bool send_exact(SOCKET s,const char* p,int count) { while(count) {int sent=send(s,p,count,0);if(sent<=0)return false;p+=sent;count-=sent;}return true; }
}
DnsPacket dns_query(const std::string& input) {
    std::string name=input; if(!name.empty() && name.back()=='.')name.pop_back();
    if(name.empty() || name.size()>253)throw std::invalid_argument("Invalid DNS name");
    DnsPacket p{0x4e,0x52,1,0,0,1,0,0,0,0,0,0};size_t begin=0;
    while(begin<name.size()) {size_t end=name.find('.',begin);if(end==std::string::npos)end=name.size();size_t len=end-begin;if(!len || len>63)throw std::invalid_argument("Invalid DNS label");p.push_back(static_cast<unsigned char>(len));for(size_t i=begin;i<end;++i) {unsigned char ch=name[i];if(!std::isalnum(ch) && ch!='-')throw std::invalid_argument("Invalid DNS character");p.push_back(ch);}begin=end+1;}
    p.push_back(0);put(p,1);put(p,1);return p;
}
DnsPacket dns_response(const DnsPacket& q,const Json& settings,const std::vector<std::string>& upstreams) {
    std::string name;size_t end{};if(!question(q,name,end))return error_response(q,1);
    bool allowed=matches(name,settings.at("allowed"));
    if(!allowed && matches(name,settings.at("blocked")))return error_response(q,3,end);
    if(settings.at("records").contains(name)) {
        auto p=error_response(q,0,end);p[2]|=4;
        if(word(q,end-4)==1 && word(q,end-2)==1) {
            in_addr ip{};auto text=settings.at("records").at(name).get<std::string>();if(inet_pton(AF_INET,text.c_str(),&ip)!=1)return error_response(q,2,end);
            p[7]=1;put(p,0xc00c);put(p,1);put(p,1);p.insert(p.end(),{0,0,0,30});put(p,4);
            auto* bytes=reinterpret_cast<unsigned char*>(&ip);p.insert(p.end(),bytes,bytes+4);
        }
        return p;
    }
    if(name=="home.arpa" || name.ends_with(".home.arpa"))return error_response(q,3,end);
    for(const auto& server:upstreams) {
        Socket s(::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP));if(s.value==INVALID_SOCKET)continue;
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(53);if(inet_pton(AF_INET,server.c_str(),&address.sin_addr)!=1)continue;
        if(connect(s.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0)continue;
        if(send(s.value,reinterpret_cast<const char*>(q.data()),int(q.size()),0)<=0 || !ready(s.value,800))continue;
        DnsPacket reply(4096);int count=recv(s.value,reinterpret_cast<char*>(reply.data()),int(reply.size()),0);
        if(count<12)continue;reply.resize(count);
        if(reply[0]==q[0] && reply[1]==q[1] && (reply[2]&0x80) && word(reply,4)==1 && reply.size()>=end && std::equal(q.begin()+12,q.begin()+end,reply.begin()+12))return reply;
    }
    return error_response(q,2,end);
}
Json dns_result(const DnsPacket& p) {
    if(p.size()<12)return {{"status","invalid"},{"origin","live"}};
    unsigned code=p[3]&15;Json out={{"status",code==0?"resolved":code==3?"NXDOMAIN":"error"},{"rcode",code},{"answers",Json::array()},{"origin","live"}};
    size_t at=12;
    auto skip=[&]() {size_t labels=0;while(at<p.size() && p[at]) {if(++labels>128)return false;if((p[at]&0xc0)==0xc0){if(at+2>p.size())return false;at+=2;return true;}auto length=p[at++];if(length>63 || at+length>p.size())return false;at+=length;}if(at>=p.size())return false;++at;return true;};
    for(unsigned i=0;i<word(p,4);++i){if(!skip() || at+4>p.size())return out;at+=4;}
    for(unsigned i=0;i<word(p,6);++i) {
        if(!skip() || at+10>p.size())break;unsigned type=word(p,at),length=word(p,at+8);at+=10;if(at+length>p.size())break;
        char address[INET6_ADDRSTRLEN]{};if(type==1 && length==4 && inet_ntop(AF_INET,p.data()+at,address,sizeof(address)))out["answers"].push_back(address);
        if(type==28 && length==16 && inet_ntop(AF_INET6,p.data()+at,address,sizeof(address)))out["answers"].push_back(address);at+=length;
    }
    return out;
}
void serve_dns(std::stop_token stop,std::function<Json()> settings,std::function<void(bool)> status) {
    Socket udp(::socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)),tcp(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(1053);inet_pton(AF_INET,"127.0.0.1",&address.sin_addr);
    if(udp.value==INVALID_SOCKET || tcp.value==INVALID_SOCKET || bind(udp.value,reinterpret_cast<sockaddr*>(&address),sizeof(address)) || bind(tcp.value,reinterpret_cast<sockaddr*>(&address),sizeof(address)) || listen(tcp.value,4)) {status(false);return;}
    status(true);auto upstream=dns_servers();if(upstream.size()>2)upstream.resize(2);
    while(!stop.stop_requested()) {
        fd_set reads{};FD_ZERO(&reads);FD_SET(udp.value,&reads);FD_SET(tcp.value,&reads);timeval timeout{0,200000};
        if(select(0,&reads,nullptr,nullptr,&timeout)<=0)continue;
        try {
            if(FD_ISSET(udp.value,&reads)) {
                DnsPacket q(4096);sockaddr_in from{};int size=sizeof(from);int count=recvfrom(udp.value,reinterpret_cast<char*>(q.data()),int(q.size()),0,reinterpret_cast<sockaddr*>(&from),&size);
                if(count>0) {q.resize(count);auto reply=dns_response(q,settings(),upstream);sendto(udp.value,reinterpret_cast<const char*>(reply.data()),int(reply.size()),0,reinterpret_cast<sockaddr*>(&from),size);}
            }
            if(FD_ISSET(tcp.value,&reads)) {
                Socket client(accept(tcp.value,nullptr,nullptr));if(client.value==INVALID_SOCKET)continue;
                DWORD millis=1000;setsockopt(client.value,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<char*>(&millis),sizeof(millis));setsockopt(client.value,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<char*>(&millis),sizeof(millis));
                unsigned char prefix[2]{};if(!receive_exact(client.value,reinterpret_cast<char*>(prefix),2))continue;int length=(prefix[0]<<8)|prefix[1];if(length<12 || length>4096)continue;
                DnsPacket q(length);if(!receive_exact(client.value,reinterpret_cast<char*>(q.data()),length))continue;
                auto reply=dns_response(q,settings(),upstream);unsigned char output[2]{static_cast<unsigned char>(reply.size()>>8),static_cast<unsigned char>(reply.size())};
                if(send_exact(client.value,reinterpret_cast<char*>(output),2))send_exact(client.value,reinterpret_cast<const char*>(reply.data()),int(reply.size()));
            }
        } catch(...) { /* A malformed local request must not stop the service. */ }
    }
    status(false);
}
}
