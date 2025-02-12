import sys
import pandas as pd
import matplotlib.pyplot as plt
import argparse

def main(paths):
    
    # Get the length of the shortest csv so we can graph
    #incomplete data
    shortest = 99999999
    for path in paths:
        perfdata = pd.read_csv(path, header=None)
        if len(perfdata[0]) < shortest:
            shortest = len(perfdata[0])

    # Create x values (positions in the array)
    x_values = list(range(shortest))
    
    plt.figure(figsize=(7,6))
        
    for path in paths:
        perfdata = pd.read_csv(path, header=None)
        perf_sorted = sorted(perfdata[0][0:shortest])
        plt.plot(x_values, perf_sorted, label=path.replace("-byte-crunch-padded_shuffleddata.csv",""), marker='o', markersize=2)

    # Add labels and title
    plt.xlabel('Position in array')
    plt.ylabel('Runtime values')
    plt.title('Sorted Runtime Values - ' + paths[0].split("-")[0])
    plt.subplots_adjust(bottom=0.5)
    plt.legend(loc="upper center", bbox_to_anchor=(0.5,-0.3), ncol=2)


    # Show the plot
    #plt.show()
    plt.savefig(paths[0].split("-")[0] + "-graph.png", format="png", dpi=300, bbox_inches="tight")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Graph data from CSV files.')
    parser.add_argument('file_paths', metavar='F', type=str, nargs='+', help='CSV file paths')
    args = parser.parse_args()
    main(args.file_paths)
