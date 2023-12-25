from flask import render_template, request, redirect, url_for, flash, session, g
from app import app
from flask_wtf.csrf import generate_csrf
from app.login import check_access
from ipblock import authenticate
import datetime
from flask import render_template, request, redirect, url_for, flash, session, g
from app import app
from flask import send_file, flash
import traceback
import os
from flask import current_app
import pandas as pd

# Import the necessary function from ipdata.py
# from .ipdata import add_ip_block, parse_ip_list
#from adminData.ipblock.ipdata import add_ip_block, parse_ip_list
from flask import request, redirect, url_for, flash, render_template
# ... other necessary imports ...

from adminData.ipblock.ipdata import getdataStart, print_results
from adminData.ipblock.ipreputaion import get_ips_with_reputations

hosts = ['192.168.0.200']
app.secret_key = 'your_secret_key_here'


#------------------- Logout after 11 minutes  ------------------
@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=11)

    if 'user_id' in session:
        g.user = session['user_id']
    else:
        g.user = None

    if request.path.startswith('/static/'):
        return

    if g.user:
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        last_activity = session.get('last_activity')
        if last_activity:
            last_activity_dt = datetime.datetime.strptime(last_activity, '%Y-%m-%d %H:%M:%S')
            if (datetime.datetime.utcnow() - last_activity_dt).total_seconds() > 660:
                session.pop('user_id', None)
                session.pop('last_activity', None)
                flash('Session timed out. Please log in again.', 'timeout')
                return redirect(url_for('loggedout'))

        session['last_activity'] = now
    elif request.endpoint not in ['login', 'loggedout']:
        return redirect(url_for('loggedout'))
    

# ---------------------------------------------------------------
    

#-------------------------- route to loginpage ------------------

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form['ADM_ID']
        password = request.form['password']
        
        access_level = check_access(user_id)

        if access_level == "write":
            connected_bigips = []
            for host in hosts:
                bigip = authenticate(user_id, password, host)
                if bigip:
                    connected_bigips.append(bigip)
            
            if len(connected_bigips) == len(hosts):
                session['user_id'] = user_id
                session['password'] = password 
                # flash('Authentication successful.', 'auth-success')
                return redirect(url_for('dashboard'))
            
            else:
                flash('Invalid credentials or unable to connect to F5 devices.', 'error')
                return redirect(url_for('login'))
        
        elif access_level == "read":
            flash("Due to read-only access you can't access this", 'info')
            return redirect(url_for('login'))
        
        else:
            flash('Invalid user ID or access level', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

# ------------------------------------------------------------



#------------------------- loggout .html redirection ---------------

@app.route('/loggedout')
def loggedout():
    return render_template('loggedout.html')


# --------------------------------------------------------


#------------------------- dashboard.html redirection ---------------

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))
    return render_template('dashboard.html')



# ----------------------------------------------------------------




#------------------------- usermanage( access of user ) .html redirection ---------------

@app.route('/userManage')
def userManage():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))
    return render_template('usermanage.html')

# ------------------------------------------------------------------



#------------------------- IP block Dashboard redirection ---------------

@app.route('/ipblockdash')
def ipblockdash():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))
    return render_template('ipblockdash.html')

# ---------------------------------------------------------------------




#--------------------------------------- IP block with reputation ----------------------




@app.route('/iprepblock', methods=['GET', 'POST'])
def iprepblock():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))

    log_directory = os.path.join(current_app.root_path, 'adminData', 'ipblock')
    log_filename = 'log.txt'
    log_file_path = os.path.join(log_directory, log_filename)

    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    if request.method == 'POST':
        cr_number = request.form.get('CRNO')
        username = session.get('user_id')
        password = session.get('password')
        invalid_ips = []
        already_added_ips = []
        ips_added_to_f5 = []
        ips_added_to_excel = []
        action_messages = []

        if 'excelFile' in request.files and request.files['excelFile']:
            file = request.files['excelFile']
            if file.filename.endswith(('.xlsx', '.xls')):
                df = pd.read_excel(file)
                ip_list = df.iloc[:, 0].dropna().astype(str).tolist()  # IPs are in the first column
            else:
                flash('Invalid file format. Please upload an Excel file.', 'error')
                return redirect(url_for('ipblock'))
        else:
            ip_list_string = request.form.get('iplist')
            ip_list = [ip.strip() for ip in ip_list_string.splitlines() if ip.strip()]

        good_ips, bad_ips = get_ips_with_reputations(ip_list)

        # Proceed with IP blocking for bad IPs
        for ip_str in bad_ips:
            messages = getdataStart(ip_str, cr_number, username, password, invalid_ips, already_added_ips, ips_added_to_f5, ips_added_to_excel)
            action_messages.extend(messages)

        # Write logs
        with open(log_file_path, 'w') as log_file:
            log_file.write("Check with SOC team (Good Reputation):\n")
            for ip in good_ips:
                log_file.write(f"{ip}\n")

            log_file.write("\nIPs added for blocking:\n")
            for ip in bad_ips:
                log_file.write(f"{ip}\n")

            log_file.write("\nInvalid IPs:\n")
            for ip in invalid_ips:
                log_file.write(ip + "\n")

            log_file.write("\nAlready present:\n")
            for message in action_messages:
                if "Skipped" in message:
                    log_file.write(message + "\n")

            log_file.write("\nIPs added to Excel:\n")
            for ip in ips_added_to_excel:
                log_file.write(ip + "\n")

        flash('IP processing completed. Check the log.txt for details.', 'success')
        return send_file(log_file_path, as_attachment=True, max_age=0)

    return render_template('iprepblock.html')


# --------------------------------------------------------------------




#-------------------------------- direct IP block --------------------------




@app.route('/ipblock', methods=['GET', 'POST'])
def ipblock():
    if 'user_id' not in session:
        flash('Please log in to continue.', 'info')
        return redirect(url_for('login'))

    log_directory = os.path.join(current_app.root_path, 'adminData', 'ipblock')
    log_filename = 'log.txt'
    log_file_path = os.path.join(log_directory, log_filename)

    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    if request.method == 'POST':
        cr_number = request.form.get('CRNO')
        username = session.get('user_id')
        password = session.get('password')
        invalid_ips = []
        already_added_ips = []
        ips_added_to_f5 = []
        ips_added_to_excel = []
        action_messages = []

        if 'excelFile' in request.files and request.files['excelFile']:
            file = request.files['excelFile']
            if file.filename.endswith(('.xlsx', '.xls')):
                df = pd.read_excel(file)
                ip_list = df.iloc[:, 0].dropna().astype(str).tolist()  # IPs are in the first column
            else:
                flash('Invalid file format. Please upload an Excel file.', 'error')
                return redirect(url_for('ipblock'))
        else:
            ip_list_string = request.form.get('iplist')
            ip_list = [ip.strip() for ip in ip_list_string.splitlines() if ip.strip()]

        for ip_str in ip_list:
            messages = getdataStart(ip_str, cr_number, username, password, invalid_ips, already_added_ips, ips_added_to_f5, ips_added_to_excel)
            action_messages.extend(messages)

        with open(log_file_path, 'w') as log_file:
            log_file.write("IPs added:\n")
            for message in action_messages:
                if "Added" in message:
                    log_file.write(message + "\n")

            log_file.write("\nInvalid IPs:\n")
            for ip in invalid_ips:
                log_file.write(ip + "\n")

            log_file.write("\nAlready present:\n")
            for message in action_messages:
                if "Skipped" in message:
                    log_file.write(message + "\n")

            log_file.write("\nIPs added to Excel:\n")
            for ip in ips_added_to_excel:
                log_file.write(ip + "\n")

        flash('IP processing completed. Check the log.txt for details.', 'success')
        return send_file(log_file_path, as_attachment=True, max_age=0)

    return render_template('ipblock.html')



@app.route('/download_log')
def download_log():
    log_directory = os.path.join(current_app.root_path, 'adminData', 'ipblock')
    log_filename = 'log.txt'
    log_file_path = os.path.join(log_directory, log_filename)
    
    try:
        return send_file(log_file_path, as_attachment=True, max_age=0)
    except FileNotFoundError:
        flash('Log file does not exist.', 'error')
        return redirect(url_for('ipblock'))
 

# -----------------------------------------------------
    


#-------------------------- admin dashboard ------------------------



@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))
    return render_template('admindash.html')


# -------------------------------------------------------------------



# --------------------------- add user access ---------------------------


@app.route('/addUser', methods=['GET', 'POST'])
def addUser():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))

    if request.method == 'POST':
        new_user_id = request.form.get('UID')
        access_type = request.form.get('userAccess')

        # Check for empty fields
        if not new_user_id or not access_type:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('addUser'))

        # Path to the acc.txt file
        acc_file_path = 'app/acc.txt'  # Update this path to the location of your acc.txt file

        # Add new user to acc.txt
        try:
            with open(acc_file_path, 'r+') as file:
                existing_users = file.readlines()
                # Check if the user already exists
                if any(new_user_id in line for line in existing_users):
                    flash('User already exists.', 'error')
                else:
                    # Move the file pointer to the end of the file to append
                    file.seek(0, os.SEEK_END)
                    # Write the new user on a new line
                    file.write(f"{new_user_id} {access_type}\n")
                    flash('User added successfully.', 'success')
        except Exception as e:
            flash(f'An error occurred: {e}', 'error')

        return redirect(url_for('addUser'))

    return render_template('addUser.html')

# ---------------------------------------------------------------

# ----------------------------- modify user access -------------------------

@app.route('/modifyUser', methods=['GET', 'POST'])
def modifyUser():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))

    if request.method == 'POST':
        user_id_to_modify = request.form.get('UID')
        new_access_type = request.form.get('userAccess')

        # Check for empty fields
        if not user_id_to_modify or not new_access_type:
            flash('Please fill in all fields.', 'error')
            return redirect(url_for('modifyUser'))

        # Prevent modification of the admin user access
        if user_id_to_modify == 'admin':
            flash("Admin will always have write access.", 'info')
            return redirect(url_for('modifyUser'))

        # Path to the acc.txt file
        acc_file_path = 'app/acc.txt'  # Update this path to the location of your acc.txt file

        # Modify user in acc.txt
        try:
            updated = False
            with open(acc_file_path, 'r') as file:
                lines = file.readlines()

            with open(acc_file_path, 'w') as file:
                for line in lines:
                    user_id, access = line.strip().split()
                    if user_id_to_modify == user_id:
                        if access == new_access_type:
                            flash(f'User already has {new_access_type} access.', 'info')
                        else:
                            line = f"{user_id_to_modify} {new_access_type}\n"
                            updated = True
                    file.write(line)

                if not updated:
                    flash('User does not exist.', 'error')
                else:
                    flash('User access modified successfully.', 'success')

        except Exception as e:
            flash(f'An error occurred: {e}', 'error')

        return redirect(url_for('modifyUser'))

    return render_template('modifyUser.html')


# --------------------------------------------------------------


# ------------------------------------- Revoke user access -----------------------


@app.route('/revokeUser', methods=['GET', 'POST'])
def revokeUser():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))

    if request.method == 'POST':
        user_id_to_revoke = request.form.get('UID')

        # Check for empty fields
        if not user_id_to_revoke:
            flash('Please enter a user ID.', 'error')
            return redirect(url_for('revokeUser'))

        # Prevent removal of the admin user
        if user_id_to_revoke == 'admin':
            flash("Admin user cannot be removed.", 'error')
            return redirect(url_for('revokeUser'))

        # Path to the acc.txt file
        acc_file_path = 'app/acc.txt'  # Update this path to the location of your acc.txt file

        # Remove user from acc.txt
        try:
            with open(acc_file_path, 'r') as file:
                lines = file.readlines()

            with open(acc_file_path, 'w') as file:
                user_found = False
                for line in lines:
                    user_id, _ = line.strip().split()
                    if user_id_to_revoke == user_id:
                        user_found = True
                        continue  # Skip writing this user to the file to remove them
                    file.write(line)

                if not user_found:
                    flash('User is not present in the database.', 'error')
                else:
                    flash('User access revoked successfully.', 'success')

        except Exception as e:
            flash(f'An error occurred: {e}', 'error')

        return redirect(url_for('revokeUser'))

    return render_template('revokeUser.html')

# -------------------------------------------------------



# ------------------------------------  all users access -------------------------


@app.route('/allUsers')
def allUsers():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))
    
    # Path to the acc.txt file
    acc_file_path = 'app/acc.txt'  # Update this path to the location of your acc.txt file
    
    # Read user details from acc.txt
    try:
        with open(acc_file_path, 'r') as file:
            user_details = [line.strip().split() for line in file]
    except Exception as e:
        flash(f'An error occurred while reading the user details: {e}', 'error')
        user_details = []

    return render_template('allUsers.html', users=user_details)

# ---------------------------------------------------------



# ------------------------ Logs dashboard -------------------- 


@app.route('/logsDash')
def logsDash():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))
    return render_template('logsdash.html')


# -------------------------- IP block logs ---------------------------
import pandas as pd
from flask import render_template, request, redirect, url_for, flash, session
@app.route('/ipblocklogs')
def ipblocklogs():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '', type=str)
    per_page = 15  # Number of records per page

    # Load data from Excel
    df = pd.read_excel('adminData/Ipblock/ipdetails.xlsx')

    # Reverse the DataFrame to display the last entries first
    df = df.iloc[::-1]

    # Implement search if the search parameter is present
    if search:
        df = df[df.apply(lambda row: row.astype(str).str.contains(search).any(), axis=1)]

    # Calculate total pages
    total_pages = (len(df) - 1) // per_page + 1

    # Get the records for the current page
    start = (page - 1) * per_page
    end = start + per_page
    records = df.iloc[start:end]

    # Convert records to HTML
    records_html = records.to_html(classes='ip-table')

    # Generate page numbers: current page, two pages before and after
    pages = range(max(1, page - 2), min(total_pages + 1, page + 3))

    return render_template('ipblocklogs.html', records_html=records_html, search=search,page=page, total_pages=total_pages,pages=pages)

# -------------------------------------------------


# ---------------------- under development routing ------------------

@app.route('/underdev')
def underdev():
    if 'user_id' not in session:
        return redirect(url_for('loggedout'))
    return render_template('underdev.html')



# ------------------------- Logout --------------------------

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('last_activity', None)
    flash('Logged out successfully.', 'logout-success')
    return redirect(url_for('loggedout'))

