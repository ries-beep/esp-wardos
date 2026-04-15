# esp-wardos
Ward OS acts like wards based on the games that used to be hidden and incoming, detecting threats. By using an ESP32 dev board with an OLED, it will make it more unnoticeable in public. This project is to be used for network environment awareness, not for illegal activities.

Needs:
1. Esp32 Dev Board
2. Oled 0.91 led
3. Wires or mini Bread board
   
Setup / wirings
OLED Pin   ESP32 Pin       Description 
GND        GND             Ground (Negative)
VCC        3.3V            Power (Positive)
SCL        GPIO 22         Serial Clock Line
SDA        GPIO 21         Serial Data Line



>>optional to add power supply to directly power the esp32<<

NOTE: user adruino IDE or Esp 32 IDE to upload the code

How to use?
1. Power the esp32
2. Connect to the esp 32 wifi to access webserver
3. Web server is used to monitor / In Oled the eye will appear and act as warning signal

Features:
1. Detects Deauth
2. Webserver Monitor
3. Detects Fake wifi
4. monitors dBm (decibels-milliwatts) is the unit used to measure Signal Strength.
5. Graph to show traffics arround
6. shows packets for each ssid
7. Oled eye will warn if theres any threats
