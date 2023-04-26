from typing import Dict, Union, Any
import ecdsa
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.template import loader
from django.forms.models import model_to_dict
from django.contrib import messages
from django.conf import settings
from django.utils import timezone
from django.contrib import messages

from Crypto.Signature import DSS
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC

import binascii
import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec


from django.urls import reverse
from .models import Voters, PoliticalParty, Vote, VoteBackup, Block, MiningInfo
from .methods_module import send_email_otp, generate_keys, verify_vote, send_email_private_key, vote_count

from .merkle_tool import MerkleTools
import datetime, json, time, random, string

import plotly.graph_objs as go
import pandas as pd
from datetime import timedelta, date
import base64

track_data = {}
apk = ''
lis = []
liv = []

# Create your views here.


# -------------- Show Vote count so far -----------

def get_voter_turnout(votes):
    # Extract the date from the timestamp in each vote object
    vote_dates = [vote.timestamp.date() for vote in votes]

    # Count the number of votes cast on each date
    date_counts = pd.Series(vote_dates).value_counts().sort_index()

    # Create a DataFrame with columns for the date and the number of votes cast
    voter_turnout = pd.DataFrame({'date': date_counts.index, 'votes_cast': date_counts.values})

    return voter_turnout



#.......................Loading Page.............................

def show_result(request):
    vote_result = vote_count()
    vote_result = dict(reversed(sorted(vote_result.items(), key = lambda vr:(vr[1], vr[0]))))
    results = []
    political_parties = PoliticalParty.objects.all()
    i=0
    for party_id, votecount in vote_result.items():
        i+=1
        party = political_parties.get(party_id = party_id)
        results.append({
            'sr': i,
            'party_name': party.party_name,
            'party_symbol': party.party_logo,
            'vote_count': votecount
        })

    party_names = [result['party_name'] for result in results]
    vote_counts = [result['vote_count'] for result in results]
    
    # Creating a pandas dataframe for voters' data with the date range of the voting period
    start_date = date(2023, 4, 25) # Change to the actual start date of the voting period
    end_date = date(2023, 4, 30) # Change to the actual end date of the voting period
    date_range = pd.date_range(start_date, end_date)
    voters_data = pd.DataFrame({'date': date_range})
    voters_data['date'] = pd.to_datetime(voters_data['date'])
    

     # Get the voter turnout data
    votes = Vote.objects.all()
    voter_turnout = get_voter_turnout(votes)
    voter_turnout['date']= pd.to_datetime(voter_turnout['date'])
    voters_data = pd.merge(voters_data, voter_turnout, on='date', how='outer')
    
    # Creating an interactive bar plot using Plotly
    colors = ['white','orange','blue']
    bar_plot = go.Figure([go.Bar(x=party_names, y=vote_counts, marker_color=colors)])
    bar_plot.update_layout(title='Votes per Political Party', xaxis_title='Political Party', yaxis_title='Number of Votes')
    bar_plot.update_traces(hovertemplate='%{x}: %{y}')
    bar_plot.update_layout(hovermode='closest')
    bar_plot.update_layout(margin=dict(l=20, r=20, t=60, b=20))

    # Creating an interactive line plot using Plotly
    line_plot = go.Figure([go.Scatter(x=voters_data['date'], y=voters_data['votes_cast'], line=dict(color='red'))])
    line_plot.update_layout(title='Voter Turnout', xaxis_title='Date', yaxis_title='Number of Voters')
    line_plot.update_traces(hovertemplate='%{x}: %{y}')
    line_plot.update_layout(hovermode='closest')
    line_plot.update_layout(margin=dict(l=20, r=20, t=60, b=20))

    # Converting the Plotly plots to div elements to send to the template
    bar_plot_div = bar_plot.to_html(full_html=False)
    line_plot_div = line_plot.to_html(full_html=False)

    # Calculate the total number of votes cast
    total_votes = sum(vote_counts)

    # Calculate the percentage of votes for each party
    vote_percentages = [100 * count / total_votes for count in vote_counts]

    # Creating an interactive pie chart using Plotly
    pie_chart = go.Figure([go.Pie(labels=party_names, values=vote_percentages)])
    pie_chart.update_layout(title='Vote Percentage per Political Party')

    # Converting the Plotly plot to a div element to send to the template
    pie_chart_div = pie_chart.to_html(full_html=False)

    return render(request, 'show-result.html', {'bar_plot': bar_plot_div, 'line_plot': line_plot_div, 'pie_chart': pie_chart_div})




def validate_authority(request):
    return render(request, 'validate.html')

def authenticate_email(request):
    details = {'success': False}
    if request.method == 'POST':
        email = request.POST.get('email')
        if email in ['bks0550@gmail.com','example1@example.com', 'example2@example.com']: 
            # generate private key
            private_key, public_key = generate_keys()
            # send private key to user's email
            send_email_private_key(email, private_key)
            # store email and private key in session
            request.session['email'] = email
            request.session['private_key'] = private_key
            return redirect(reverse('verify_key'))
        else:
            details = {
            'success':False,
             'message': 'You are not Authorized'
            }
            return JsonResponse(details)
    return redirect(reverse('validate'))

def verify_key(request):
    if request.session.get('email') and request.session.get('private_key'):
        if request.method == 'POST':
            private_key = request.POST.get('private_key')
            vf = private_key
            private_key = private_key.replace('\n', '').replace(' ','')
            print("submitted key :"+ private_key)
            print('\n')
            print("generated key :"+request.session['private_key'].replace('\n', '').replace(' ',''))
            if private_key == request.session['private_key'].replace('\n', '').replace(' ',''):
                # email and private key matched, user is verified
                messages.success(request, 'Private key verified!')
                apk = vf
                return redirect(reverse('mine-block'))
            else:
                # private key doesn't match, redirect to verification page again
                messages.error(request, 'Private key does not match.')
                return redirect(reverse('verify_key'))
        else:
            return render(request, 'verify_key.html', {'email': request.session['email']})
    else:
        # email and private key not found in session, redirect to verification page
        return redirect(reverse('authenticate_email'))

def mine_block(request):
    if request.session.get('email') and request.session.get('private_key'):
        to_seal_votes_count = Vote.objects.all().filter(block_id=None).count()
        return render(request, 'mine-block.html', {'data': to_seal_votes_count})
    else:
        return redirect(reverse('authenticate_email'))

# ----------------- Start mining on button click ---------------
def start_mining(request):
    if request.session.get('email') and request.session.get('private_key'):
        data = create_block(request)
        html = loader.render_to_string('mined-blocks.html', data)
        return JsonResponse({'html': html})
    else:
        return redirect(reverse('authenticate_email'))





# --------------- Authentication -------------------
def authentication(request):
    voter = ""
    aadhar_no = request.POST.get('aadhar_no')
    details = {'success': False}
    try:
        voter = Voters.objects.get(uuid=aadhar_no)
        request.session['uuid'] = aadhar_no
        render_html = loader.render_to_string('candidate_details.html', {'details': voter})
        if voter.vote_done:
            details = {
                'error': 'You have already casted your vote.'
            }
        else:
            request.session['email-id'] = voter.email
            details = {
                'success': True,
                'html': render_html,
                'details': model_to_dict(voter)
            }
    except:
        details = {
            'error': 'Invalid Voter Id, Please recheck you card number!'
        }

    return JsonResponse(details)


# --------- On successful email verfication show all parties options ----------
def get_parties(request):

    request.session['email-verified'] = True
    
    party_list = {}
    if request.session['email-verified']:

        private_key, public_key = generate_keys()

        send_email_private_key(request.session['email-id'], private_key)
        # print(private_key)

        request.session['public-key'] = public_key

        parties = list(PoliticalParty.objects.all())
        parties = [model_to_dict(party) for party in parties]

        render_html = loader.render_to_string('voting.html', {'parties': parties})

        party_list = {
            'html': render_html,
            'parties': parties
        }

    return JsonResponse(party_list)


def create_vote(request):
    uuid = request.session['uuid']

    private_key = request.POST.get('private-key')
    public_key = request.session['public-key']

    selected_party_id = request.POST.get('selected-party-id')

    curr = timezone.now()

    ballot = f'{uuid}|{selected_party_id}|{curr.timestamp()}'

    status = verify_vote(private_key, public_key, ballot)
    context = {'success': status[0], 'status': status[1]}

    if status[0]:
        try:
            Vote(uuid=uuid, vote_party_id=selected_party_id, timestamp=curr).save()
            VoteBackup(uuid=uuid, vote_party_id=selected_party_id, timestamp=curr).save()
            voter = Voters.objects.get(uuid=request.session['uuid'])
            voter.vote_done = True
            voter.save()
        except Exception as e:
            context['status'] = 'We are not able to save your vote. Please try again. ' + str(e) + '.'

    html = loader.render_to_string('final-status.html', {
        'ballot': status[2], 'ballot_signature': status[3], 'status': status[1]})
    context['html'] = html

    return JsonResponse(context)


# -------------- Home--------------
def home(request):
    return render(request, 'home.html')


# -------------- create Dummy Data ------------------
def create_dummy_data(request):
    to_do = {
        'createRandomVoters': json.loads(request.GET.get('createRandomVoters')) if request.GET.get('createRandomVoters') else None,
        'createPoliticianParties': json.loads(request.GET.get('createPoliticianParties')) if request.GET.get('createPoliticianParties') else None,
        'castRandomVote': json.loads(request.GET.get('castRandomVote')) if request.GET.get('castRandomVote') else None,
    }
    if to_do['createRandomVoters'] or to_do['createPoliticianParties'] or to_do['castRandomVote']:
        dummy_data_input(to_do)
        return JsonResponse({'success': True})
    return render(request, 'create-dummy-data.html')
    # dummy_data_input()
    # return redirect('/')





# Create block [called in start_mining()]
def create_block(request):
    if request.session.get('email') and request.session.get('private_key'):
        # Get mining info upto last mining
        mining_info = MiningInfo.objects.all().first()
        prev_hash = mining_info.prev_hash
        curr_block_id = last_block_id = int(mining_info.last_block_id)

        non_sealed_votes = Vote.objects.all().filter(block_id=None).order_by('timestamp')
        non_sealed_votes_BACKUP = VoteBackup.objects.all().filter(block_id=None).order_by('timestamp')





        # Get settings for per block mining
        txn_per_block = 5
        number_of_blocks = int( non_sealed_votes.count()/txn_per_block )


        time_start = time.time()

        result = []

        track_data['progress'] = True
        track_data['status'] = 'Mining has been Initialised.'
        track_data['completed'] = 0
        t = 0

        for _ in range(number_of_blocks):
            # As soon as block_id set to the transaction it is automatically removed from 'non_sealed_vote'
            # Hence always top 'txn_per_block' transactions belong to one block
            block_transactions = non_sealed_votes[t:t+txn_per_block]
            block_transactions_BACKUP = non_sealed_votes_BACKUP[t:t+txn_per_block]

            t = t + txn_per_block
            

            ##creating merkle hash
            root = MerkleTools()
            root.add_leaf([f'{tx.uuid}|{tx.vote_party_id}|{tx.timestamp}' for tx in block_transactions], True)
            li = [f'{tx.uuid}|{tx.vote_party_id}|{tx.timestamp}' for tx in block_transactions]
            root.make_tree()
            merkle_h = root.get_merkle_root()


            # Try to seal the block and generate valid hash
            timestamp = timezone.now()
            nonce = random.randint(0, 100000)

            enc = f'{prev_hash}{merkle_h}{nonce}{timestamp.timestamp()}'
            

            signer = DSS.new(ECC.import_key(request.session.get('private_key')), 'fips-186-3')
            print("Signer", signer)
            print("inside the verify function 2")
            ballot_hash = SHA3_256.new(enc.encode())
            signature = signer.sign(ballot_hash)

            h=ballot_hash.hexdigest()

            # Create the block
            curr_block_id += 1

            block_data = []

            for vote in non_sealed_votes:
                vote_data = {
                    'uuid': str(vote.uuid),
                    'vote_party_id': vote.vote_party_id,
                    'timestamp': str(vote.timestamp)
                }
                block_data.append(vote_data)


            Block(id=curr_block_id, prev_hash=prev_hash, merkle_hash=merkle_h, this_hash=h, nonce=nonce, timestamp=timestamp,data=li,signer_address=signature).save()
            
            

            result.append({
                'block_id': curr_block_id, 'prev_hash': prev_hash, 'merkle_hash': merkle_h, 'this_hash': h, 'nonce': nonce,'data':block_data,'signer_address':signature
            })
            
            # Set this hash as prev hash
            prev_hash = h
            
            # Set block_id to every transaction
            for txn in block_transactions:
                txn.block_id = str(curr_block_id)
                txn.save()
            for txn in block_transactions_BACKUP:
                txn.block_id = str(curr_block_id)
                txn.save()

            track_data['status'] = str(curr_block_id - last_block_id) + ' blocks have been mined. (' + str((curr_block_id - last_block_id)*txn_per_block) + ' vote transactions have been sealed.)'
            track_data['completed'] = round((curr_block_id - last_block_id)*100/number_of_blocks)
        time_end = time.time()

        time_taken = time_end - time_start
        if time_taken < 0.0000:
            time_taken = 0.000000

        # Save current Mining info
        mining_info.prev_hash = prev_hash
        mining_info.last_block_id = str(curr_block_id)
        mining_info.id = 0
        mining_info.save()

        data = {
            'time_taken': round(time_end-time_start, 6),
            'result': result
        }

        track_data['progress'] = False

        return data
    else:
        return redirect(reverse('authenticate_email'))

def dummy_data_input(to_do):

    track_data['progress'] = True
    track_data['status'] = 'Deleting current Data.'
    track_data['completed'] = 0
    
    PoliticalParty.objects.all().delete()
    Voters.objects.all().delete()
    Vote.objects.all().delete()
    Block.objects.all().delete()
    VoteBackup.objects.all().delete()
    MiningInfo.objects.all().delete()

    track_data['completed'] = 100
    track_data['status'] = 'Deleted current Data.'

    MiningInfo(id = 0, prev_hash = '0'*64, last_block_id = '0').save()

    if to_do['createPoliticianParties']:

        parties = {
            'nota': {
                'party_id': 'nota',
                'party_name': 'None of the above (NOTA)',
                'party_logo': 'https://upload.wikimedia.org/wikipedia/commons/thumb/a/a4/NOTA_Option_Logo.png/220px-NOTA_Option_Logo.png',
                'candidate_name': '',
                'candidate_profile_pic': ''
            }
        }

        track_data['completed'] = 0
        track_data['status'] = 'Creating parties.'

        # Create Parties
        for party in parties.values():
            PoliticalParty(party_id = party['party_id'], party_name = party['party_name'], party_logo = party['party_logo']).save()
            curr = list(parties.keys()).index(party['party_id'])+1
            track_data['completed'] = round(curr*100/len(parties))

    if to_do['createRandomVoters']:

        track_data['completed'] = 0
        track_data['status'] = 'Creating voters.'

        # Create Voters
        no_of_voters = 10
        for i in range(1, no_of_voters+1):
            # uuid = ''.join(random.choice(string.digits) for _ in range(12))
            uuid = i
            name = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(12))
            dob = datetime.date(random.randint(1980, 2002), random.randint(1, 12), random.randint(1, 28))
            pincode = ''.join(random.choice(string.digits) for _ in range(6))
            region = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase) for _ in range(20))
            voter = Voters(uuid = uuid, name = name, dob = dob, pincode = pincode, region = region).save()
            track_data['completed'] = round(i*100/no_of_voters)

    if to_do['castRandomVote'] and to_do['createRandomVoters'] and to_do['createPoliticianParties']:

        track_data['completed'] = 0
        track_data['status'] = 'Creating votes.'

        # Create Votes
        party_ids = list(parties.keys())
        for i in range(1, no_of_voters+1):
            curr_time = timezone.now()
            party_id = party_ids[random.randint(0,len(party_ids)-1)]
            Vote(uuid = i, vote_party_id = party_id, timestamp = curr_time).save()
            VoteBackup(uuid = i, vote_party_id = party_id, timestamp = curr_time).save()
            voter = Voters.objects.get(uuid=i)
            voter.vote_done = True
            voter.save()
            track_data['completed'] = round(i*100/no_of_voters)

    track_data['status'] = 'Finishing task.'
    track_data['progress'] = False

def blockchain(request):
    blocks = Block.objects.all()
    return render(request, 'blockchain.html', {'blocks':blocks})

def block_info(request):
    try:
        block = Block.objects.get(id=request.GET.get('id'))
        confirmed_by = (Block.objects.all().count() - block.id) + 1

        votes = Vote.objects.filter(block_id=request.GET.get('id'))
        vote_hashes = [SHA3_256.new((f'{vote.uuid}|{vote.vote_party_id}|{vote.timestamp}').encode('utf-8')).hexdigest() for vote in votes]

        root = MerkleTools()
        root.add_leaf([f'{vote.uuid}|{vote.vote_party_id}|{vote.timestamp}' for vote in votes], True)
        root.make_tree()
        merkle_hash = root.get_merkle_root()
        tampered = block.merkle_hash != merkle_hash
        
        context = {
            'this_block': block,
            'confirmed_by': confirmed_by,
            'votes': zip(votes, vote_hashes),
            're_merkle_hash': merkle_hash,
            'isTampered': False,
        }
        return render(request, 'block-info.html', context)
    except Exception as e:
        # print(str(e))
        return render(request, 'block-info.html')

def sync_block(request):
    try:
        block_id = request.GET.get('block-id')
        # print(block_id)
        # print(Vote.objects.filter(block_id=block_id))
        backup_votes = VoteBackup.objects.filter(block_id=block_id).order_by('timestamp')
        # print(backup_votes)
        for vote in backup_votes:
            x_vote = Vote.objects.get(uuid=vote.uuid)
            x_vote.vote_party_id = vote.vote_party_id
            x_vote.timestamp = vote.timestamp
            x_vote.block_id = vote.block_id
            x_vote.save()
        return JsonResponse({'success': True})
    except Exception as e:
        # print(e)
        return JsonResponse({'success': False})

def verify_block(request):
    selected = request.GET.getlist('selected[]')
    print(selected)
    context = {}
    for s_block in selected:
        print(s_block)
        block = Block.objects.get(id=s_block)
        votes = Vote.objects.filter(block_id=s_block)
        vote_hashes = [SHA3_256.new((f'{vote.uuid}|{vote.vote_party_id}|{vote.timestamp}').encode('utf-8')).hexdigest() for vote in votes]
        li = [f'{vote.uuid}|{vote.vote_party_id}|{vote.timestamp}' for vote in votes]
        print("******************")
        print(li)
        print(block.data)
        print("******************")
        root = MerkleTools()
        root.add_leaf([f'{vote.uuid}|{vote.vote_party_id}|{vote.timestamp}' for vote in votes], True)
        root.make_tree()
        merkle_hash = root.get_merkle_root()
        print("***********")
        print(s_block)
        print(merkle_hash)
        print(block.merkle_hash)
        print("***********")
        tampered = block.merkle_hash != merkle_hash
        context[s_block] = False
    return JsonResponse(context)

def track_server(request):
    return JsonResponse(track_data)


