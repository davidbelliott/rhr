from flask import Flask, render_template
import csv

app = Flask(__name__)
app.config.from_object('config')

@app.route('/')
def index():
    with open("students.txt") as tsv:
        rows = [line for line in csv.reader(tsv, dialect="excel-tab")]
        columns = list(zip(*rows))
        print(rows)
        print(columns)
        student_names = columns[0]
    return render_template('index.html', student_names=student_names)
