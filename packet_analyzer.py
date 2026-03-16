import tkinter as tk
from tkinter import ttk
from scapy.all import sniff
import threading

tcp_count = 0
udp_count = 0
icmp_count = 0
total_packets = 0
capturing = False


def analyze_packet(packet):
    global tcp_count, udp_count, icmp_count, total_packets

    if packet.haslayer("IP"):
        ip = packet["IP"]

        protocol = "Other"

        if ip.proto == 6:
            protocol = "TCP"
            tcp_count += 1
        elif ip.proto == 17:
            protocol = "UDP"
            udp_count += 1
        elif ip.proto == 1:
            protocol = "ICMP"
            icmp_count += 1

        total_packets += 1

        # Insert into table
        table.insert("", "end",
                     values=(ip.src, ip.dst, protocol, len(packet)))

        # Update counters
        tcp_label.config(text=f"TCP: {tcp_count}")
        udp_label.config(text=f"UDP: {udp_count}")
        icmp_label.config(text=f"ICMP: {icmp_count}")
        total_label.config(text=f"Total Packets: {total_packets}")


def capture_packets():
    global capturing
    while capturing:
        sniff(count=1, prn=analyze_packet)


def start_capture():
    global capturing
    if not capturing:
        capturing = True
        status_label.config(text="Status: Capturing", fg="green")
        threading.Thread(target=capture_packets, daemon=True).start()


def stop_capture():
    global capturing
    capturing = False
    status_label.config(text="Status: Stopped", fg="red")


def clear_table():
    for row in table.get_children():
        table.delete(row)


root = tk.Tk()
root.title("Network Packet Analyzer")
root.geometry("800x500")

title = tk.Label(root, text="Network Packet Analyzer",
                 font=("Arial", 18, "bold"))
title.pack(pady=10)

# Counters
counter_frame = tk.Frame(root)
counter_frame.pack()

tcp_label = tk.Label(counter_frame, text="TCP: 0", font=("Arial", 12))
tcp_label.grid(row=0, column=0, padx=20)

udp_label = tk.Label(counter_frame, text="UDP: 0", font=("Arial", 12))
udp_label.grid(row=0, column=1, padx=20)

icmp_label = tk.Label(counter_frame, text="ICMP: 0", font=("Arial", 12))
icmp_label.grid(row=0, column=2, padx=20)

total_label = tk.Label(counter_frame, text="Total Packets: 0", font=("Arial", 12))
total_label.grid(row=0, column=3, padx=20)

# Buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

start_btn = tk.Button(button_frame, text="Start Capture",
                      command=start_capture, bg="green", fg="white", width=15)
start_btn.grid(row=0, column=0, padx=10)

stop_btn = tk.Button(button_frame, text="Stop Capture",
                     command=stop_capture, bg="red", fg="white", width=15)
stop_btn.grid(row=0, column=1, padx=10)

clear_btn = tk.Button(button_frame, text="Clear Screen",
                      command=clear_table, bg="blue", fg="white", width=15)
clear_btn.grid(row=0, column=2, padx=10)

status_label = tk.Label(root, text="Status: Idle")
status_label.pack()

# Packet table
columns = ("Source IP", "Destination IP", "Protocol", "Length")

table = ttk.Treeview(root, columns=columns, show="headings", height=15)

for col in columns:
    table.heading(col, text=col)
    table.column(col, width=180)

table.pack(pady=10)

root.mainloop()
