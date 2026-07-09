import os
import csv

base_dir = os.path.dirname(os.path.abspath(__file__))

input_csv = os.path.join(base_dir, "verified_online.csv")
output_txt = os.path.join(base_dir, "output.txt")

with open(input_csv, "r", encoding="utf-8") as csvfile, \
     open(output_txt, "w", encoding="utf-8") as txtfile:

    reader = csv.reader(csvfile)
    for row in reader:
        txtfile.write(" ".join(row) + "\n")

print("Done!")