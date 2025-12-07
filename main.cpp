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
        PDU* pduPtr = &pdu;
        //Log to console that a new packet was recieved and being processed
        //Log the packets type and size
        while(pduPtr->inner_pdu() != nullptr){
            if(pduPtr->inner_pdu()->pdu_type() == PDU::RAW) break;
            pduPtr = pduPtr->inner_pdu();
        }
        std::cout << "\n______________________________________________________________________________\n";
        std::cout 
        << "Processing new packet:" 
        << "\nUnderlying Packet Type: " << Utils::to_string(pduPtr->pdu_type()) 
        << "\nFull Packet Size: "<<pdu.advertised_size() << " bytes"
        << std::endl;
        
        IP* pduIPv4 = pdu.find_pdu<IP>();
        if(pduIPv4 != 0){
            //If packet has a valid IPv4 address source and destination, print them
            std::cout 
            << "Source: " << pduIPv4->src_addr() 
            << "\nDestination: " << pduIPv4->dst_addr();
            std::cout << "\n______________________________________________________________________________\n";
        }
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
        if(sniffer.set_filter(filter)) std::cout << "Error: invalid filter provided! Using unfiltered mode\n";
        sniffer.sniff_loop(process_packet_callback);
    }
    void start_snorting_filter(Sniffer& sniffer, const std::string filter, const int max_packet_count){
        if(max_packet_count <= 0) {
            std::cout << "Invalid max_packet_count inputted\n";
            return;
        }
        if(sniffer.set_filter(filter)) std::cout << "Error: invalid filter provided! Using unfiltered mode\n";
        sniffer.sniff_loop(process_packet_callback, max_packet_count);
    }
};

namespace PacketSnorterARP{

};

namespace PacketSnorterApp{
    PCKSN_STATE process_input(char* input){
        PCKSN_STATE return_state = PCKSN_EXIT;
        std::string input_str(input);
        if(input_str == "f") return_state = PCKSN_FILTERED;
        else if(input_str == "a") return_state = PCKSN_ARP;

        return return_state;
    }

    void process_state(const PCKSN_STATE state, char* argv[], Sniffer& sniffer){
        switch(state){
            case PCKSN_UNFILTERED:
                PacketSnorterSniffer::start_snorting_no_filter(sniffer);
                break;
            case PCKSN_FILTERED:
                if (argv[2] != nullptr) PacketSnorterSniffer::start_snorting_filter(sniffer, argv[2]);
                else{
                    std::cout << "Error: invalid filter provided! Using unfiltered mode\n";
                    PacketSnorterSniffer::start_snorting_no_filter(sniffer);
                }
                break;
            case PCKSN_ARP:
                
                break;
            default:
                std::cout << "Error: Invalid modifier was given! Application exiting...\n";
                break;
        }
    }

    void run_app(const int argc, char* argv[], Sniffer& sniffer){
        if(argc <= 1) {
            process_state(PCKSN_UNFILTERED, argv, sniffer);
        }
        else process_state(process_input(argv[1]), argv, sniffer);
    }

};

int main(int argc, char* argv[]) {
    if(argc > 3){
        std::cout << "Error: Invalid argument count!\n";
        return -1;
    }

    SnifferConfiguration config;
    config.set_immediate_mode(true);
    config.set_promisc_mode(true);

    Sniffer sniffer("eth0", config);

    PacketSnorterApp::run_app(argc, argv, sniffer);

    return 0;
}

