#include <iostream>
#include <tins/tins.h>

using namespace Tins;

//PCKSN = Packet Snort State
//These states represent the different modes the user can select when running
enum PCKSN_STATE{
    PCKSN_EXIT = 0,
    PCKSN_UNFILTERED, PCKSN_FILTERED, PCKSN_ARP
};

//Namespace for packet sniffer functions
namespace PacketSnorterSniffer{
    //Callback function that is called everytime a packet is processed.
    //This function is responsible for processing packets whenever they are picked up by a packet sniffer
    bool process_packet_callback(PDU& pdu)
    {
        PDU* pduPtr = &pdu;

        //libtins uses a layered approach to their packet capture, allowing packets to be "peeled" away
        //This peels each packet layer until it reaches the bottom layer or almost the bottom layer of the packet
        while(pduPtr->inner_pdu() != nullptr){
            //If the next layer is the raw data of the packet, leave loop
            if(pduPtr->inner_pdu()->pdu_type() == PDU::RAW) break;
            pduPtr = pduPtr->inner_pdu();
        }

        std::cout << "\n______________________________________________________________________________\n";
        std::cout 
        //Log to console that a new packet was recieved and being processed
        //Log the packets type and size
        << "Processing new packet:" 
        << "\nUnderlying Packet Type: " << Utils::to_string(pduPtr->pdu_type()) 
        << "\nFull Packet Size: "<<pdu.advertised_size() << " bytes"
        << std::endl;
        
        //Find IP address data if present
        IP* pduIPv4 = pdu.find_pdu<IP>();
        if(pduIPv4 != 0){
            //If packet has a valid IPv4 address source and destination, print them
            std::cout 
            << "Source: " << pduIPv4->src_addr() 
            << "\nDestination: " << pduIPv4->dst_addr();
            std::cout << "\n______________________________________________________________________________\n";
        }

        //Find ARP Hardware address if present
        ARP* pduARP = pdu.find_pdu<ARP>();
        if(pduARP != 0){
            std::cout 
            << "Hardware Address: " << pduARP->sender_hw_addr() 
            << std::endl;
        }
        return true;
    }   
    
    //Starts packet sniffing without a filter
    void start_snorting_no_filter(Sniffer& sniffer){
        sniffer.sniff_loop(process_packet_callback);
    }

    //Starts packet capture with a filter
    void start_snorting_filter(Sniffer& sniffer, const std::string filter){
        if(!sniffer.set_filter(filter)) std::cout << "Error: invalid filter provided! Using unfiltered mode\n";
        sniffer.sniff_loop(process_packet_callback);
    }
};

namespace PacketSnorterARP{
    //Uses the network interface to determine the address range for mappable IP addresses in the local subnet
    IPv4Range find_address_range(NetworkInterface& network){
        std::cout 
        << "Network Name: "        << network.name()         << std::endl 
        << "Network Address: "     << network.ipv4_address() << std::endl 
        << "Network Subnet Mask: " << network.ipv4_mask()    << std::endl << std::endl;

        return IPv4Range::from_mask(network.ipv4_address(), network.ipv4_mask());
    }

    //Uses the local subnet IP range to iterate through each address and send an ARP request.
    //The PacketSender will wait for a response until its default timeout
    //If it gets a response_packet, process the packets IP Address and Hardware address and print to console
    void send_arp_requests(NetworkInterface& network){
        IPv4Range range = find_address_range(network);
        for(const auto& addr : range){
            EthernetII request = ARP::make_arp_request(addr, network.info().ip_addr, network.info().hw_addr);
            PacketSender sender(network, 1);
            std::unique_ptr<PDU> response_packet(sender.send_recv(request, network));
            if(response_packet){
                ARP& arp = response_packet->rfind_pdu<ARP>();
                std::cout << "______________________________________________________________________________\n";
                std::cout 
                << "Hardware Device IPv4 Address: " << arp.sender_ip_addr() << std::endl
                << "Hardware Device Address: " << arp.sender_hw_addr();
                std::cout << "\n______________________________________________________________________________\n\n";
            }
        }
        
    }
};

namespace PacketSnorterApp{
    //Process the modifier input following the command
    PCKSN_STATE process_input(char* input){
        PCKSN_STATE return_state = PCKSN_EXIT;
        std::string input_str(input);
        if(input_str == "f") return_state = PCKSN_FILTERED;
        else if(input_str == "a") return_state = PCKSN_ARP;

        return return_state;
    }

    //Processes whatever the current state of the command is and starts functionality
    void process_state(const PCKSN_STATE state, char* argv[], Sniffer& sniffer, NetworkInterface& network){
        switch(state){
            case PCKSN_UNFILTERED:
                PacketSnorterSniffer::start_snorting_no_filter(sniffer);
                break;
            case PCKSN_FILTERED:
                if (argv[2] != nullptr) {
                    std::string filter(argv[2]);
                    PacketSnorterSniffer::start_snorting_filter(sniffer, filter);
                }
                else{
                    std::cout << "Error: invalid filter provided! Using unfiltered mode\n";
                    PacketSnorterSniffer::start_snorting_no_filter(sniffer);
                }
                break;
            case PCKSN_ARP:
                PacketSnorterARP::send_arp_requests(network);
                break;
            default:
                std::cout << "Error: Invalid modifier was given! Application exiting...\n";
                break;
        }
    }

    //Function to start packet processing
    void run_app(const int argc, char* argv[], Sniffer& sniffer, NetworkInterface& network){
        if(argc <= 1) {
            process_state(PCKSN_UNFILTERED, argv, sniffer, network);
        }
        else process_state(process_input(argv[1]), argv, sniffer, network);
    }

};

int main(int argc, char* argv[]) {
    if(argc > 3){
        std::cout << "Error: Invalid argument count!\n";
        return -1;
    }

    //The default network interface, usually eth0
    NetworkInterface network = NetworkInterface::default_interface();

    //Configure the packet sniffer to immediately recieve packets and sets promiscuous mode
    SnifferConfiguration config;
    config.set_immediate_mode(true);
    config.set_promisc_mode(true);

    Sniffer sniffer(network.name(), config);

    PacketSnorterApp::run_app(argc, argv, sniffer, network);

    return 0;
}