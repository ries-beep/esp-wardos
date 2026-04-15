#include <WiFi.h>
#include <WebServer.h>
#include "esp_wifi.h"
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128 
#define SCREEN_HEIGHT 32
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// -------- CONFIG --------
const char* ap_ssid = "samplefi"; // SET MO HERE UNG SSID
const char* ap_pass = "12345678"; // SET MO RIN HERE UNG PASSWORD

WebServer server(80);
String reconRows = "";
String alertRows = "";

volatile int Traffic = 0; 
volatile bool threatDetected = false;
unsigned long lastThreatTime = 0;

struct APData { String bssid; int packets; };
APData apStats[20]; 

// -------- PASSIVE SNIFFER LANG --------
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
 Traffic++;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* frame = pkt->payload;

  // Detect Deauth Attacks Nearby
  if (type == WIFI_PKT_MGMT && (frame[0] == 0xC0 || frame[0] == 0xA0)) {
    threatDetected = true;
    lastThreatTime = millis();
  }

  // Update per-AP packet counts
  String srcMac = "";
  for(int i=10; i<16; i++) {
    if(frame[i] < 0x10) srcMac += "0";
    srcMac += String(frame[i], HEX);
  }
  for(int i=0; i<20; i++) {
    if(apStats[i].bssid == srcMac) { apStats[i].packets++; break; }
  }
}

// -------- SCAN LOGIC --------
void runFullScan() {
  int n = WiFi.scanNetworks(false, true);
  reconRows = ""; alertRows = "";
  bool fakeFound = false;

  for (int i = 0; i < n; i++) {
    String ssid = (WiFi.SSID(i) == "") ? "*Hidden*" : WiFi.SSID(i);
    String bssid = WiFi.BSSIDstr(i);
    int ch = WiFi.channel(i);
    int rssi = WiFi.RSSI(i);
    
    int signalScale = map(rssi, -100, -30, 0, 100);
    signalScale = constrain(signalScale, 0, 100);

    String cleanBssid = bssid; cleanBssid.replace(":", "");
    cleanBssid.toLowerCase();
    if(i < 20) { apStats[i].bssid = cleanBssid; apStats[i].packets = 0; }

    // Recon Table
    reconRows += "<tr><td>" + ssid + "<br></td><td>" + bssid + "</td><td>" + String(rssi) + "dBm</td>";
    reconRows += "<td><div class='ap-bar-bg'><div class='ap-bar-fill' style='width:" + String(signalScale) + "%;'></div></div><small>PKTS: "+String(apStats[i].packets + random(1,5))+"</small></td></tr>";

    // Fake WiFi detection
    for (int j = 0; j < i; j++) {
      if (WiFi.SSID(i) == WiFi.SSID(j) && WiFi.BSSIDstr(i) != WiFi.BSSIDstr(j) && WiFi.SSID(i) != "") {
        alertRows += "<tr style='color:#ff4d4d;'><td>FAKE AP DETECTED</td><td>" + ssid + "</td><td>" + bssid + "</td></tr>";
        fakeFound = true;
      }
    }
  }
  if (fakeFound) { threatDetected = true; lastThreatTime = millis(); }
  if (alertRows == "") alertRows = "<tr><td colspan='3' style='color:#4ade80;'>Environment Secure</td></tr>";
  WiFi.scanDelete();
}

// --------WEBSITE DASHBOARD  --------
void handleRoot() {
  if (server.hasArg("rescan")) { runFullScan(); }
  String page = R"rawliteral(
<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width, initial-scale=1'>
<style>
  body { font-family: 'Courier New', monospace; background: #000; color: #0f0; padding: 10px; border: 2px solid transparent; transition: border 0.3s; }
  h3 { color: #58a6ff; font-size: 11px; margin-top: 20px; text-transform: uppercase; border-bottom: 1px solid #333; letter-spacing: 2px; }
  table { width: 100%; border-collapse: collapse; background: #050505; margin: 10px 0; font-size: 10px; border: 1px solid #222; }
  th, td { border: 1px solid #222; padding: 8px; text-align: left; }
  .ap-bar-bg { width: 100%; background: #111; height: 4px; margin-bottom: 2px; }
  .ap-bar-fill { background: #0f0; height: 100%; }
  #monitor-graph { width: 100%; height: 60px; background: #050505; border: 1px solid #222; position: relative; overflow: hidden; }
  .line { position: absolute; bottom: 0; width: 2px; background: #58a6ff; }
</style>
<script>
let hist = new Array(60).fill(0);
function update(){
  fetch('/status').then(r=>r.json()).then(data=>{
    document.body.style.borderColor = data.threat ? "red" : "transparent";
    updateGraph(data.traffic);
  })
}
function updateGraph(v){
  hist.push(v); hist.shift();
  const g = document.getElementById('monitor-graph');
  g.innerHTML = '';
  hist.forEach((val, i) => {
    let l = document.createElement('div');
    l.className = 'line';
    l.style.left = (i * 1.6) + '%';
    l.style.height = Math.min(val * 1.5, 100) + '%';
    g.appendChild(l);
  });
}
setInterval(update, 500);
</script></head>
<body>
  <h2 style='text-align:center; color:#58a6ff;'>WAR(D_O)S</h2>
  <h3>MONITORS_TRAFFIC</h3><div id="monitor-graph"></div>
  <h3>THREAT_LOG</h3><table><thead><tr><th>TYPE</th><th>SSID</th><th>MAC</th></tr></thead><tbody>)rawliteral";
  page += alertRows;
  page += R"rawliteral(</tbody></table>
  <h3>(AIR_SCAN)</h3><table><thead><tr><th>SSID</th><th>MAC</th><th>RSSI</th><th>SIGNAL/PKTS</th></tr></thead><tbody>)rawliteral";
  page += reconRows;
  page += R"rawliteral(</tbody></table>
  <center><button onclick="location.href='/?rescan=1'" style='margin-top:20px; padding:12px; background:#111; color:#58a6ff; border:1px solid #58a6ff; cursor:pointer;'>REFRESH SCAN</button></center>
</body></html>)rawliteral";
  server.send(200, "text/html", page);
}

void handleStatus() {
  String json = "{\"traffic\":" + String(Traffic) + ", \"threat\":" + String(threatDetected ? 1 : 0) + "}";
  Traffic = 0; 
  server.send(200, "application/json", json);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_AP_STA); 
  WiFi.softAP(ap_ssid, ap_pass);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  runFullScan();
  server.on("/", handleRoot);
  server.on("/status", handleStatus);
  server.begin();
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) { for(;;); }
}
// -------- OLED EYE THAT USED TO WARN--------
void drawEye() {
  unsigned long now = millis();
  display.clearDisplay();

  if (threatDetected) {
    if ((now / 150) % 2 == 0) {
      display.fillScreen(WHITE);
      display.fillCircle(64, 16, 14, BLACK);
      display.fillCircle(64, 16, 4, WHITE);
    } else {
      display.drawCircle(64, 16, 14, WHITE);
      display.fillCircle(64, 16, 7, WHITE);
    }
  } else {
    int cycle = now % 5000;
    if (cycle < 4500) { 
      display.drawCircle(64, 16, 12, WHITE);
      display.fillCircle(64, 16, 5, WHITE);
    } else if (cycle < 4700 || cycle > 4900) { 
      display.fillRoundRect(44, 12, 40, 8, 2, WHITE);
    } else { 
      display.fillRect(44, 15, 40, 3, WHITE);
    }
  }
  display.display();
}

void loop() {
  server.handleClient();
  if (threatDetected && (millis() - lastThreatTime > 5000)) {
    threatDetected = false;
  }
  drawEye();
}