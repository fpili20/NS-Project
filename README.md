# Project Goals: Multi-Threshold IoT Network Traffic Classifier

This document outlines the core objectives and goals of the Network Security project. Enhance the baseline threshold-based Network Traffic Classifier (NTC)
 by designing and implementing a multi-criteria decision logic based on multiple transport protocols (TCP, UDP, and ICMP percentages)
 to improve classification robustness and reduce false classification rates.

## Core Objectives

### 1. Data Preprocessing
Load the ToN_IoT dataset, map the 9 malicious sub-classes and normal traffic into two macro-classes (Benevolent and Malevolent), and shuffle the dataset to remove temporal patterns
.

### 2. Multi-Feature Extraction
Segment traffic into sequential blocks (e.g., 1000 packets)
 and calculate the concurrent distribution (%) of TCP, UDP, and ICMP packets within the same loop
.

### 3. Combined Threshold Rule Design
Implement a compound logical rule (e.g., $TCP\% > T_1 \land UDP\% < T_2$) to separate malicious blocks from benign oneslock.

### 4. Performance Evaluation
Validate the classifier and calculate a complete set of metrics studied in the theoretical lectures: Accuracy, Precision, Recall (TPR), and False Positive Rate (FPR).

## How to run
The dataset isn't meant to be versioned so the .csv file is contained in the .gitignore.
To run the code just add train_test_network.csv file in the data directory