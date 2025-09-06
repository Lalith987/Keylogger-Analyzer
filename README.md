# Advanced Threat Analysis Console

An all-in-one cybersecurity utility built with Python and Tkinter for real-time system monitoring, keylogging demonstration, and threat analysis. This tool features a sophisticated, dark-themed GUI inspired by modern security operations centers.

!(link_to_your_screenshot.png) <!-- Don't forget to add a screenshot! -->

## Features

-   **Multi-Tabbed Interface**: A clean and intuitive GUI separates the three core functions:
    -   **Keylogger**: A live, multi-threaded keylogger to demonstrate capture techniques.
    -   **Process Scanner**: Scans all running processes using a keyword-based heuristic engine.
    -   **Network Monitor**: Detects all processes with active, established internet connections.
-   **Interactive Details Panel**: Select any process in the scanner lists to instantly view critical details like PID, user, creation time, file path, and parent process.
-   **Persistent Whitelist**: Right-click any process to add it to a `whitelist.json` file, hiding it from future scans to reduce noise.
-   **Direct Process Termination**: Terminate any suspicious process directly from the UI by selecting it or entering its PID.

## Technologies Used

-   **Language**: Python
-   **GUI**: Tkinter / ttk
-   **System Interaction**: `psutil`
-   **Keystroke Capture**: `pynput`
-   **Threading**: Python's `threading` module
-   **Data Persistence**: JSON

## Setup and Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/lalith987/Keylogger-Analyzer.git
    cd Keylogger_Analyzer
    ```

2.  Install the required libraries:
    ```bash
    pip install psutil pynput
    ```

3.  Run the application:
    ```bash
    python Keylogger_Analyzer.py
    ```
    *Note: For full functionality (especially network scanning and process termination), it is recommended to run the script with administrator privileges.*

## How to Use

1.  **Keylogger**: Navigate to the `> Keylogger_` tab and click "Initiate Capture" to start logging keystrokes.
2.  **Process Scanner**: Go to the `> Process_Scanner_` tab and click "Execute Scan" to find suspicious processes.
3.  **Network Monitor**: Go to the `> Network_Monitor_` tab and click "Scan Connections" to see all processes with active internet connections.
4.  **View Details**: Click on any process in the scanner lists to populate the details panel below.
5.  **Whitelist**: Right-click on a process in either scanner list and select "Add to Whitelist" to ignore it in the future.
6.  **Terminate**: Click the "Terminate Process" button and enter the PID of the target process.
