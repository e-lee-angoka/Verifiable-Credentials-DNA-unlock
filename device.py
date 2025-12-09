# Code for the device

import requests # to make http requests
import json # to facilitate data transfer
import didkit # for verifiable credentials
from datetime import datetime, timezone # for timestamps
from flask import Flask, request, jsonify # to run as a server
import threading # to run server in background

class DeviceClient:
    def __init__(self, device_id, base_url='http://localhost:5000', device_port=6000):
        self.device_id = device_id
        self.base_url = base_url  # Factory server at port 5000
        self.device_port = device_port  # Device's own server at port 6000 (different from factory!)
        #self.manufacturer_credential = None  # Credential issued by manufacturer
        self.manufacturer_public_key = None  # Manufacturer's public key for verification
        self.registration_jwk = None # keypair used to register future keys
        self.registration_did = None
        self.registration_verification_method = None
        self.jwk = None # keypair used for general authentication
        self.did = None
        self.verification_method = None # for the general verification key
        self.verifiable_credential = None
        self.app = None  # Flask app instance
        self.server_thread = None  # Thread for running server
        
    def provision_from_factory(self):
        '''Request a long-term keypair from the factory'''
        print("\n" + "=" * 60)
        print("Provisioning Device with Factory-generated Registration keypair")
        print("=" * 60)
        print(f" Requesting registration keypair from factory for {self.device_id}...")

        url = f'{self.base_url}/api/devices/provision'
        payload = {'device_id': self.device_id}

        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            response_data = response.json()

            # in practice this will be OOB so no need to cryptographically verify
            print(f"  ✓ Received response")

            # Extract the keypair and identity information
            registration_jwk_dict = response_data.get('jwk')
            self.registration_jwk = json.dumps(registration_jwk_dict)
            self.registration_did = response_data.get('did')
            self.registration_verification_method = response_data.get('verification_method')

            # Extract manufacturer information
            manufacturer_public_key_dict = response_data.get('manufacturer_public_key')
            self.manufacturer_public_key = json.dumps(manufacturer_public_key_dict)
            #self.manufacturer_credential = response_data.get('credential')

            print(f"  ✓ Received long-term registration keypair")
            print(f"     Registration key: {self.registration_jwk}")
            print(f"     Registration public key (x): {registration_jwk_dict.get('x')}")
            print(f"     Registration DID: {self.registration_did}")
            print(f"     Registration Verification method: {self.registration_verification_method}")
            print(f"  ✓ Received manufacturer information")
            print(f"     Manufacturer public key (x): {manufacturer_public_key_dict}")
            #print(f"     Manufacturer VC: {self.manufacturer_credential}")

            return True
        except requests.exceptions.RequestException as e:
            print(f"  ✗ Provisioning failed: {e}")
            return False

    def create_profile(self):
        print("\n" + "-" * 60)
        print("This is where the profile build will happen")
        print("-" * 60)
        return True

    def generate_key(self):
        '''Generate an EdDSA key pair using DIDKit'''
        print("\n" + "=" * 60)
        print("Generating EdDSA key pair for "+self.device_id+"...")
        print("=" * 60)

        # Generate a new Ed25519 key
        self.jwk = didkit.generateEd25519Key()
        jwk_dict = json.loads(self.jwk)
        print(f" ✓ Public key (x): {jwk_dict.get('x')}")
        self.verification_method = didkit.keyToVerificationMethod("key", self.jwk)
        # Get the verification method
        self.verification_method = didkit.keyToVerificationMethod("key", self.jwk)
        print(f"✓ Verification method: {self.verification_method}")

        # Get the DID from the key
        print("Generating DID from EdDSA key pair...")
        self.did = didkit.keyToDID("key", self.jwk)
        print(f" ✓ DID: {self.did}")

        return self.jwk
    
    def register_key(self):
        '''Register this device with the manufacturer, sending signed request'''
        print("\n" + "=" * 60)
        print(f"Registering {self.device_id}'s auth key with manufacturer...")
        print("=" * 60)

        if not self.registration_jwk:
            print("No registration key, must provision from factory first")
            return False

        jwk_dict = json.loads(self.registration_jwk)

        # Send only public key information (not the private key 'd')
        public_key = {
            'kty': jwk_dict.get('kty'),
            'crv': jwk_dict.get('crv'),
            'x': jwk_dict.get('x'),
            'use': jwk_dict.get('use')  # Optional but good to include
        }
        # Get verification method from device key
        verification_method = didkit.keyToVerificationMethod("key", self.jwk)

        # Create a verifiable credential containing the registration data
        print(f"Creating signed registration request...")
        registration_credential = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                {
                    "DeviceRegistrationRequest": "https://example.org/credentials#DeviceRegistrationRequest",
                    "device_id": "https://example.org/credentials#deviceId",
                    "public_key_jwk": "https://example.org/credentials#publicKeyJwk",
                    "did": "https://example.org/credentials#did",
                    "verification_method": "https://example.org/credentials#verificationMethod"
                }
            ],
            "type": ["VerifiableCredential", "DeviceRegistrationRequest"],
            "issuer": self.registration_did,
            "issuanceDate": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "credentialSubject": {
                "device_id": self.device_id,
                "public_key_jwk": json.dumps(public_key),  # Serialize as string to avoid JSON-LD expansion issues
                "did": self.did,
                "verification_method": verification_method
            }
        }

        # Sign the registration request with the registration key
        proof_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": self.registration_verification_method
        }

        try:
            signed_registration = didkit.issueCredential(
                json.dumps(registration_credential),
                json.dumps(proof_options),
                self.registration_jwk
            )
            signed_registration_dict = json.loads(signed_registration)
            print(f"✓ Registration request signed with registration key")
        except Exception as e:
            print(f"✗ Error signing registration request: {e}")
            return False

        url = f'{self.base_url}/api/devices/register'
        payload = {
            'signed_registration': signed_registration_dict
        }

        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            response_data = response.json()
            
            print(f"\nKey registered successfully!")
            
            # Store the manufacturer's public key credential
            self.verifiable_credential = response_data.get('credential')
            
            if self.verifiable_credential:
                print(f"\n✓ Received own verifiable credential credential!")
                print(f"   Credential type: {self.verifiable_credential.get('type')}")
                print(f"   Issuer: {self.verifiable_credential.get('issuer')}")
                print(f"   Subject: {self.verifiable_credential.get('credentialSubject', {}).get('id')}")
                """
                # Verify the manufacturer's credential
                print(f"\nVerifying manufacturer's credential...")
                try:
                    verify_options = json.dumps({"proofPurpose": "assertionMethod"})
                    verification_result = didkit.verifyCredential(
                        json.dumps(self.manufacturer_credential),
                        verify_options
                    )
                    result_dict = json.loads(verification_result)
                    
                    if len(result_dict.get('errors', [])) == 0:
                        print(f"✓ Manufacturer credential verified successfully!")
                    else:
                        print(f"✗ Manufacturer credential verification failed: {result_dict.get('errors')}")
                except Exception as e:
                    print(f"✗ Error verifying manufacturer credential: {e}")
                """
            
            #print(f"\nFull registration response:")
            #print(json.dumps(response_data, indent=2))
            return True
        except requests.exceptions.RequestException as e:
            print(f"Registration failed: {e}")
            return False

    def generate_presentation(self, challenge, gateway_did):
        '''Generate a verifiable presentation in response to a challenge'''
        print("\n" + "=" * 60)
        print(f"Generating verifiable presentation for challenge...")
        print("=" * 60)

        if not self.verifiable_credential:
            print("✗ No credential available to present")
            return None

        if not self.jwk:
            print("✗ No key available for signing presentation")
            return None

        print(f"Challenge: {challenge[:16]}...")
        print(f"Gateway DID: {gateway_did}")

        # Clean the JWK - only keep standard fields required by DIDKit
        jwk_dict = json.loads(self.jwk)
        cleaned_jwk = {
            'kty': jwk_dict.get('kty'),
            'crv': jwk_dict.get('crv'),
            'x': jwk_dict.get('x'),
            'd': jwk_dict.get('d')  # Private key component
        }
        # Remove any None values
        cleaned_jwk = {k: v for k, v in cleaned_jwk.items() if v is not None}
        cleaned_jwk_str = json.dumps(cleaned_jwk)

        # Create a verifiable presentation
        # The presentation includes the credential and is signed by the device
        # NOTE: challenge goes in proof_options, NOT in the presentation itself
        presentation = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "type": ["VerifiablePresentation"],
            "holder": self.did,
            "verifiableCredential": [self.verifiable_credential]
        }

        # Proof options for signing the presentation
        # Challenge is included here to bind the proof to this specific authentication attempt
        proof_options = {
            "proofPurpose": "authentication",
            "verificationMethod": self.verification_method,
            "challenge": challenge
        }

        try:
            # Sign the presentation using DIDKit with cleaned JWK
            signed_presentation = didkit.issuePresentation(
                json.dumps(presentation),
                json.dumps(proof_options),
                cleaned_jwk_str
            )

            vp = json.loads(signed_presentation)
            print(f"✓ Verifiable presentation generated and signed")
            print(f"   Holder: {vp.get('holder')}")
            print(f"   Credentials: {len(vp.get('verifiableCredential', []))}")

            return vp

        except Exception as e:
            print(f"✗ Error generating presentation: {e}")
            print(f"   JWK fields present: {list(cleaned_jwk.keys())}")
            print(f"   Verification method: {self.verification_method}")
            return None

    def handle_challenge(self, challenge, gateway_did):
        '''Handle an authentication challenge from a gateway'''
        print("\n" + "=" * 60)
        print(f"Received authentication challenge from gateway")
        print("=" * 60)
        print(f" challenge: {challenge}")

        # Generate and return the verifiable presentation
        vp = self.generate_presentation(challenge, gateway_did)

        if vp:
            print(f"✓ Ready to send verifiable presentation to gateway")
            return vp
        else:
            print(f"✗ Failed to generate verifiable presentation")
            return None

    def setup_server(self):
        '''Set up Flask server for receiving challenges'''
        print("\n" + "=" * 60)
        print(f"Setting up device server on port {self.device_port}...")
        print("=" * 60)

        self.app = Flask(f"Device-{self.device_id}")

        # Store reference to self for use in route handlers
        device_instance = self

        @self.app.route('/challenge', methods=['POST'])
        def receive_challenge():
            '''Endpoint to receive authentication challenges'''
            data = request.json
            challenge = data.get('challenge')
            gateway_did = data.get('gateway_did')

            if not challenge or not gateway_did:
                return jsonify({'error': 'Missing challenge or gateway_did'}), 400

            # Generate VP using the device instance
            vp = device_instance.handle_challenge(challenge, gateway_did)

            if vp:
                return jsonify({'verifiable_presentation': vp}), 200
            else:
                return jsonify({'error': 'Failed to generate verifiable presentation'}), 500

        @self.app.route('/status', methods=['GET'])
        def status():
            '''Health check endpoint'''
            return jsonify({
                'device_id': device_instance.device_id,
                'did': device_instance.did,
                'status': 'active',
                'has_credential': device_instance.verifiable_credential is not None
            }), 200

        print(f"✓ Server routes configured")

    def start_server(self):
        '''Start the Flask server in a background thread'''
        if not self.app:
            print("✗ Server not set up. Call setup_server() first.")
            return False

        print("\n" + "=" * 60)
        print(f"Starting device server on http://localhost:{self.device_port}")
        print("=" * 60)

        def run_server():
            self.app.run(
                host='0.0.0.0',
                port=self.device_port,
                debug=False,
                use_reloader=False
            )

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        print(f"✓ Device server running on port {self.device_port}")
        print(f"   Challenge endpoint: http://localhost:{self.device_port}/challenge")
        print(f"   Status endpoint: http://localhost:{self.device_port}/status")

        return True

    """
    def issue_credential(self, message):
        '''Self-issue a verifiable credential with a message'''
        if not self.jwk:
            print("No key available for signing")
            return None
        
        #print(f"\nFull JWK before signing:")
        #print(self.jwk)
        
        print(f"\nCreating verifiable credential with message: {message}")
        
        # Create a simple verifiable credential
        credential = {
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": ["VerifiableCredential"],
            "issuer": self.did,
            "issuanceDate": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "credentialSubject": {
                "id": self.did
            }
        }
        
        # Proof options for signing
        options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": self.verification_method
        }
        
        #print(f"Credential to sign:")
        #print(json.dumps(credential, indent=2))
        #print(f"\nOptions:")
        #print(json.dumps(options, indent=2))
        
        try:
            # Issue the credential using DIDKit
            signed_credential = didkit.issueCredential(
                json.dumps(credential),
                json.dumps(options),
                self.jwk
            )
            
            print("Credential issued successfully!")
            return signed_credential
        except Exception as e:
            print(f"Error issuing credential: {e}")
            print(f"Error type: {type(e)}")
            return None
    
    def send_credential(self, message):
        '''Issue and send a credential to the manufacturer'''
        credential = self.issue_credential(message)
        
        if not credential:
            return False
        
        url = f'{self.base_url}/api/devices/{self.device_id}/verify-credential'
        payload = {
            'credential': json.loads(credential) if isinstance(credential, str) else credential,
            'message': message  # Send message separately does this mean message isn't signed?
        }
        
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            print(f"Credential sent: {response.json()}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to send credential: {e}")
            return False
    """

def main():
    print("*" * 60)
    print("Device Client")
    print("*" * 60)

    # Create a device instance
    test_id = 'DEVICE-001'
    device = DeviceClient(device_id=test_id)
    print(f"{test_id} initialised.")

    # Step 1: Request long-term keypair from factory
    try:
        if not device.provision_from_factory():
            print("Failed to provision device, exiting")
            return
    except Exception as e:
        print(f"Error during provisioning: {e}")
        return
    
    # Step 2: Build profile
    if not device.create_profile():
        print("Failed to create profile from characteristics, exiting")
        return

    # Step 3: Generate local keypair
    if not device.generate_key():
        print("Failed to generate device local keypair, exiting")
        return

    # Step 4: Register public key with manufacturer
    if not device.register_key():
        print("Failed to register device key, exiting")
        return

    # Step 5: Set up and start device server
    device.setup_server()
    if not device.start_server():
        print("Failed to start device server, exiting")
        return

    #print("\n" + "=" * 60)
    print("------Device registration and server startup completed!-----\n")
    print("=" * 60)
    print(f"\n\nDevice {test_id} is now ready to receive authentication challenges.")
    print(f" Server listening on http://localhost:{device.device_port}...")
    #print("=" * 60)

    # Keep the main thread alive so the server continues running
    try:
        print("\nPress Ctrl+C to stop the device server...")
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down device server...")

if __name__ == '__main__':
    main()