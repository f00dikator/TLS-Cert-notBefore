package main

import (
	"fmt"
        "log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)

func handle_appdata(buf []byte) int {
	ret := 0
	buf_len := len(buf)

	// 0x301e170d <12 bytes> 0x5a
	for idx, _ := range buf {
       		if ((idx + 6) < buf_len) && (buf[idx] == 0x16) && (buf[idx+1] == 0x03) && (buf[idx+5] == 0x0b) {
			ret++
			buf_ptr := idx
			for buf_ptr < buf_len {
				if ((buf_ptr+18) < buf_len) && (buf[buf_ptr] == 0x30) && (buf[buf_ptr+1] == 0x1e) &&
				   (buf[buf_ptr+2] == 0x17) && (buf[buf_ptr+3] == 0x0d) {
					buf_ptr += 4
					fmt.Printf("Certificate created on date:\n")
					fmt.Printf("20%c%c-%c%c-%c%c %c%c:%c%c:%c%c", buf[buf_ptr], buf[buf_ptr+1],
						buf[buf_ptr+2], buf[buf_ptr+3], buf[buf_ptr+4], buf[buf_ptr+5],
						buf[buf_ptr+6], buf[buf_ptr+7], buf[buf_ptr+8],
						buf[buf_ptr+9], buf[buf_ptr+10], buf[buf_ptr+11])
					fmt.Printf("\nIP Info:\n")
					return ret
				}
				buf_ptr++
			}
         	}
	}

	return ret 
}




func main() {

	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever)
	if err != nil {
                fmt.Printf("%s\n", "Error opening en0")
		log.Fatal(err)
	}


	var filter string = "tcp[(tcp[12]>>4)*4] == 0x16 and tcp[((tcp[12]>>4)*4)+1] == 0x03"
	err = handle.SetBPFFilter(filter)
	if err != nil {
                fmt.Printf("%s\n", "Failed to set BPF Filter")
        	log.Fatal(err)
	}


	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
                if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
			fmt.Printf("Que Demonios es eso?!? No packet. Onward and upward")
 			continue
 		} else {
			applicationLayer := packet.ApplicationLayer()
    			if applicationLayer != nil {
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
    				if ipLayer != nil {
        				ip, _ := ipLayer.(*layers.IPv4)
					appdata := applicationLayer.Payload()
					retval := handle_appdata(appdata)
					if (retval != 0) {
						fmt.Printf("%s -> %s\n\n", ip.SrcIP, ip.DstIP)
						// if you want to write out the full packet, uncomment the line below
						// fmt.Printf("%s", packet.Dump())
					}
				}
 			}
		}
	}
}

