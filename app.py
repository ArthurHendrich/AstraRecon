from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import subprocess
import os

app = Flask(__name__)
DATABASE = 'results.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        with open('db/init.sql', 'r') as f:
            conn.executescript(f.read())
        conn.commit()

def add_result(tool, target, result):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO results (tool, target, result) VALUES (?, ?, ?)', (tool, target, result))
        conn.commit()

def get_results(tool, target):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('SELECT result FROM results WHERE tool = ? AND target = ?', (tool, target))
        return c.fetchall()

# Initialize the database
init_db()

# Function to run a script and store its output in the database
def run_script(script_name, tool, target):
    result = subprocess.run(['python', f'scripts/{script_name}.py', target], capture_output=True, text=True)
    add_result(tool, target, result.stdout)
    return result.stdout

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Route for subfinder
@app.route('/subfinder', methods=['GET', 'POST'])
def subfinder():
    if request.method == 'POST':
        target = request.form['target']
        result = run_script('subfinder_script', 'Subfinder', target)
        return render_template('results.html', tool='Subfinder', target=target, results=result.split('\n'))
    return render_template('subfinder.html')

# Route for assetfinder
@app.route('/assetfinder', methods=['GET', 'POST'])
def assetfinder():
    if request.method == 'POST':
        target = request.form['target']
        result = run_script('assetfinder_script', 'Assetfinder', target)
        return render_template('results.html', tool='Assetfinder', target=target, results=result.split('\n'))
    return render_template('assetfinder.html')

# Route for httpx
@app.route('/httpx', methods=['GET', 'POST'])
def httpx():
    if request.method == 'POST':
        target = request.form['target']
        result = run_script('httpx_script', 'HTTPX', target)
        return render_template('results.html', tool='HTTPX', target=target, results=result.split('\n'))
    return render_template('httpx.html')

# Results route
@app.route('/results/<tool>/<target>')
def results(tool, target):
    db_results = get_results(tool, target)
    results = [r[0] for r in db_results]
    return render_template('results.html', tool=tool, target=target, results=results)

if __name__ == '__main__':
    app.run(debug=True)
