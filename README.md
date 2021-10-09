# DoorLock
Arduino code running on an ESP8266 that opens the door lock in the PTL, using LDAP and RFID

## Build steps

Get the `ptldap` library:

    git submodule update --init

### With `Arduino IDE`

Install the following libraries:

    MFRC522

Click on the `Upload` button and you're done!

### With `arduino-cli`
Install platform for esp8266

    arduino-cli config init
    arduino-cli config set board_manager.additional_urls "https://arduino.esp8266.com/stable/package_esp8266com_index.json"
    arduino-cli core update-index
    arduino-cli core install esp8266:esp8266
    
Install libraries, compile and upload:

    arduino-cli lib install MFRC522
    arduino-cli lib install FastLED
    arduino-cli compile --fqbn esp8266:esp8266:d1_mini --build-property compiler.cpp.extra_flags=-fexceptions --build-property build.stdcpp_lib=-lstdc++-exc
    arduino-cli upload --port /dev/ttyUSB0 --fqbn esp8266:esp8266:d1_mini
