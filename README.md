# Cyber-Attack-Detection using IOT
This project detects cyber attacks in IoT networks using machine learning algorithms like Support Vector Machine (SVM) and Artificial Neural Network (ANN). It focuses on identifying abnormal patterns from IoT device data to enhance network security.

 ## Objectives
Use supervised ML models (SVM, ANN) to classify normal vs. malicious traffic.
Apply to real-world IoT systems with various sensors and actuators.
Provide an early alert system for threats like spoofing, DDoS, data injection, etc.

## Technologies Used
 Language: Python
 ML Algorithms: SVM, ANN (Keras/TensorFlow or PyTorch)
 Libraries: scikit-learn, pandas, matplotlib, seaborn, TensorFlow/Keras
 Tools: Jupyter Notebook, VS Code
 Dataset: [Custom or TON_IoT, BoT-IoT]

## Sensors and Actuators Used
This project simulates or uses data from the following types of IoT components:
### Sensors:
Temperature Sensor – Monitors heat changes.
Humidity Sensor – Tracks moisture in the environment.
Motion Sensor (PIR) – Detects movement.
Gas Sensor – Detects harmful gases (e.g., MQ2).
Ultrasonic Sensor – Measures distance (for physical intrusion detection).

### Actuators:
Servo Motor – Controlled movement based on conditions.
Relay Module – Turns devices ON/OFF in response to anomalies.
Buzzer/Alarm – Alerts when an attack is detected.
## ML Workflow
Data Preprocessing – Normalization, feature extraction.
Model Training:
SVM: Effective for small- to medium-sized datasets.
ANN: Detects complex patterns; ideal for noisy IoT data.
Evaluation – Accuracy, confusion matrix, ROC-AUC.
## Future Improvements
Integrate with real-time MQTT brokers.
Add online learning for adapting to new threats.
Implement on Raspberry Pi or ESP32 for edge computing.
