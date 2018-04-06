# Xiaomi-Mijia-Bluetooth-Temperature-and-Humidity-Sensor

Developed starting from Bluez hcitool, this tool is able to
read the data sent as BLE advertisements by the Xiaomi
Mijia Bluetooth temperature and humidity sensor.

You should have already installed the Bluetooh Bluez stack.

Issue 'make' to build the tool. 
Then issue scanMijia -h to show detailed help.

Like the original hcitool command, also this tool should be
run from root.

If you are curious, look into SensorProtocol.html file in order to to
know some details of the protocol used by this sensor.
