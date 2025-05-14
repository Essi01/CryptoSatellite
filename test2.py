import pandas as pd
# Compute total latency (encrypt + decrypt + 50 ms delay) per algorithm/board and print in seconds
# This script calculates the total latency for different encryption algorithms on various boards,

# Define latency data: [encryption µs, decryption µs]
data = {
    "Verdin": {
        "AES Software": [[62.06, 337.35], [31.90, 156.67], [540790, 2999410]],
        "SPECK":        [[38.53, 36.14],  [33.42, 62.08],  [56462, 57531.6]],
        "ASCON":        [[23.19, 22.05],  [14.20, 13.15],  [113476.02, 113511.83]],
        "ChaCha20":     [[12.86, 12.85],  [17.44, 17.44],  [82519.7, 85167.1]]
    },
    "Portenta X8": {
        "AES Software": [[86.985, 466.574], [31.9041, 156.674], [702949, 4034340]],
        "SPECK":        [[81.5647, 79.1709], [71.5484, 81.1717], [74720.8, 75997.5]],
        "ASCON":        [[73.75, 53.89], [64.21, 44.18], [42121.29, 41528.55]],
        "ChaCha20":     [[17.4466, 17.4947], [17.4405, 17.4414], [112660, 112637]]
    },
    "Portenta H7": {
        "AES Hardware": [[14.16, 13.84], [9.11, 9.27], [6933.11, 6941.42]],
        "AES Software": [[43.91, 269.14], [32.36, 181.54], [2406.07, 17790.98]],
        "SPECK":        [[12.54, 8.36], [7.34, 4.07], [219.63, 100.53]],
        "ASCON":        [[33.63, 31.04], [21.86, 19.87], [350.41, 349.44]],
        "ChaCha20":     [[13.15, 10.97], [12.88, 10.59], [485.32, 476.66]]
    }
}

# Set communication delay (in µs)
delay_us = 50000

# Calculate total latencies with delay and convert to seconds
results = {}
for board, algos in data.items():
    board_result = []
    for algo, tests in algos.items():
        row = [algo]
        for enc, dec in tests:
            total_latency = enc + dec + delay_us
            total_seconds = total_latency / 1_000_000
            row.append(round(total_seconds, 6))
        board_result.append(row)
    results[board] = pd.DataFrame(board_result, columns=["Algorithm", "Test 1 (s)", "Test 2 (s)", "Test 3 (s)"])

# Print each board's result
for board, df in results.items():
    print(f"\n=== {board} Total Latency in Seconds (50ms Delay) ===")
    print(df.to_string(index=False))
