# SmartTravel
[Prototype] Local travel digital payments built with Flask.


Uses:
ESP32 Modeule, Rfid sensors, Rfid cards, jumpers, bread-boards.
Arduino IDE, Pycharm IDE.

Scenario:
1. Scan user RFID card while boarding train at initial station. (Can't scan the same station for both initial an final entry.)
2. Scan user RFID card while deboarding train at final station. (Can't scan another station until previous payment is done.)
3. Server calculates the ticket cost and stores it in the database.
4. User needs to login on the website and go to 'Profile' page to pay your ticket due by clicking on the pay button.
5. Will create an successful payment reciept page with order_id as per the RazorPay testing mode conditions.
6. User history will get recorded.
7. User is now eligible to scan again. 
