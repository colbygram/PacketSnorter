#include <iostream>
#include <tins/tins.h>

using namespace Tins;

//PCKSN = Packet Snort State
//These states represent the different modes the user can select when running
enum PCKSN_STATE{
    PCKSN_EXIT = 0,
    PCKSN_UNFILTERED, PCKSN_FILTERED, PCKSN_ARP
};

namespace PacketSnorterSniffer{
    
    bool process_packet_callback(PDU& pdu)
    {
        std::cout 
        << "Processing new packet!\n";
        std::cout 
        << "Source: " << pdu.rfind_pdu<IP>().src_addr() 
        << " Destination: " << pdu.rfind_pdu<IP>().dst_addr() 
        <<std::endl;
        return true;
    }   
    
    void start_snorting_no_filter(Sniffer& sniffer){
        sniffer.sniff_loop(process_packet_callback);
    }
    void start_snorting_no_filter(Sniffer& sniffer, const int max_packet_count){
        if(max_packet_count <= 0) {
            std::cout << "Invalid max_packet_count inputted\n";
            return;
        }
        sniffer.sniff_loop(process_packet_callback, max_packet_count);
    }

    void start_snorting_filter(Sniffer& sniffer, const std::string filter){
        sniffer.set_filter(filter);
        sniffer.sniff_loop(process_packet_callback);
    }
    void start_snorting_filter(Sniffer& sniffer, const std::string filter, const int max_packet_count){
        if(max_packet_count <= 0) {
            std::cout << "Invalid max_packet_count inputted\n";
            return;
        }
        sniffer.set_filter(filter);
        sniffer.sniff_loop(process_packet_callback, max_packet_count);
    }
};

namespace PacketSnorterARP{

};

namespace PacketSnorterApp{
    PCKSN_STATE process_input(const char input){
        PCKSN_STATE return_state = PCKSN_EXIT;
        switch (input)
        {
            case 'u':
                return_state = PCKSN_UNFILTERED;
                break;
            case 'f':
                return_state = PCKSN_FILTERED;
                break;
            case 'a':
                return_state = PCKSN_ARP;
                break;    
            default:
                break;
        }
        return return_state;
    }
    void process_state(const PCKSN_STATE state){

    }
    void run_app(){

    }

};

int main() {  
    SnifferConfiguration config;
    config.set_immediate_mode(true);
    config.set_promisc_mode(true);
    Sniffer sniffer("eth0", config);

    PacketSnorterSniffer::start_snorting_no_filter(sniffer, 1);

    PacketSnorterApp::run_app();

    return 0;
}

