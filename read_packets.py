import pyshark
from datetime import datetime

def check_test_pattern(df, tp_start_index: int) -> None:
    flag = False
    past_value = 0
    for i in range(len(df[tp_start_index:])//3):
        new_val = int(df[tp_start_index+2 + i*3]+df[tp_start_index+3 + i*3], 16)
        past_value = (past_value + 1) % 256
        if new_val == past_value:
            continue
        flag = True
        print("Out of order!", new_val, past_value)

    if flag: 
        print("Failed!")




capture: pyshark.LiveCapture = pyshark.LiveCapture(interface="eth0") #display_filter='ip.src == 192.168.10.102'
# capture.set_debug()
# capture.sniff(packet_count=1000)
tp_start = 19

first_capture = True
current_df_counter = 0
for packet in capture.sniff_continuously():
    if 'DVB-S2_MODEADAPT' in packet:
        
        df = packet["dvb-s2_bb"].df
        new_df_counter = int("".join(df[:11].split(':')) , 16)
        new_modeadapt_counter = int(packet["dvb-s2_modeadapt"].frameno)
        # print(f'{new_df_counter}  {datetime.now()}  {len(df)//3 + 1}  {int(packet["dvb-s2_bb"].dfl)//8}')
        check_test_pattern(df, tp_start)
        
        if first_capture:
            current_df_counter = new_df_counter
            current_modeadapt_counter = new_modeadapt_counter
            first_capture = False
        
        elif not first_capture:
            if new_df_counter == (current_df_counter + 1) % 4294967296:  # might as well include it ;-; (when counter reches its max and resets to 0)
                pass
            else:
                print("tp counter of order", new_df_counter, current_df_counter)
            current_df_counter = new_df_counter

            if new_modeadapt_counter == (current_modeadapt_counter + 1) % 256:
                pass
            else:
                print("frame number of order", new_modeadapt_counter, current_modeadapt_counter)
            current_modeadapt_counter = new_modeadapt_counter



capture.close()


"""
VERIFY:

packet counter in modeadapt layer

tp counter - done
tp payload size (12e4) - done
tp payload - done
"""