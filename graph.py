import sys
import pandas as pd
import matplotlib.pyplot as plt

def main(perf1_path, perf2_path):
    # Read the CSV files
    perf1 = pd.read_csv(perf1_path, header=None)
    perf2 = pd.read_csv(perf2_path, header=None)

    # Sort the arrays
    perf1_sorted = sorted(perf1[0])
    perf2_sorted = sorted(perf2[0])

    # Create x values (positions in the array)
    x_values = list(range(len(perf1_sorted)))

    # Plot the data
    plt.plot(x_values, perf1_sorted, label='perf1', marker='o', markersize=2)
    plt.plot(x_values, perf2_sorted, label='perf2', marker='o', markersize=2)

    # Add labels and title
    plt.xlabel('Position in array')
    plt.ylabel('Runtime values')
    plt.title('Sorted Runtime Values')
    plt.legend()

    # Show the plot
    plt.show()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <perf1.csv> <perf2.csv>")
        sys.exit(1)

    perf1_path = sys.argv[1]
    perf2_path = sys.argv[2]

    main(perf1_path, perf2_path)