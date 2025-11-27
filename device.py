# Code for the device

# Generate DID
# Await "trigger provisioning"

# Stage 1.2: Send DID to manufacturer
#  triggered by receiving "trigger provisioning" request

# Stage 1.3: Receive VC from manufacturer

# Stage 2.2 Send VP (Verifiable Presentation) to user_gateway
#  triggered by receiving challenge
#  generates VP using challenge and VC


import requests # to make http requests
import json # to facilitate data transfer
import didkit # for verifiable credentials
from datetime import datetime, timezone # for timestamps

class DeviceClient:
    def __init__(self, device_id, base_url='http://localhost:5000'):
        self.device_id = device_id
        self.base_url = base_url
        self.jwk = None
        self.did = None
        self.verification_method = None
        
    def generate_key(self):
        '''Generate an EdDSA key pair using DIDKit'''
        print("Generating EdDSA key pair...")
        
        # Generate a new Ed25519 key
        self.jwk = didkit.generateEd25519Key()
        jwk_dict = json.loads(self.jwk)
        
        # Get the DID from the key
        self.did = didkit.keyToDID("key", self.jwk)
        
        # Get the verification method
        self.verification_method = didkit.keyToVerificationMethod("key", self.jwk)
        
        print(f"Key generated successfully!")
        print(f"DID: {self.did}")
        print(f"Public key (x): {jwk_dict.get('x')}")
        
        return self.jwk
    
    def register(self):
        '''Register this device with the manufacturer, sending public key'''
        if not self.jwk:
            print("No key generated yet, generating now...")
            self.generate_key()
        
        jwk_dict = json.loads(self.jwk)
        
        # Send only public key information (not the private key 'd')
        public_key = {
            'kty': jwk_dict.get('kty'),
            'crv': jwk_dict.get('crv'),
            'x': jwk_dict.get('x'),
            #'use': jwk_dict.get('use')  # Optional but good to include
        }

        # Debug: print what we're sending
        #print(f"\nPublic key being sent:")
        #print(json.dumps(public_key, indent=2))
        
        url = f'{self.base_url}/api/devices/register'
        payload = {
            'device_id': self.device_id,
            'public_key_jwk': public_key,
            'did': self.did,
            'verification_method': self.verification_method
        }
        #print(f"\nPayload: {payload}")
        
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            print(f"\nDevice registered successfully!")
            print(json.dumps(response.json(), indent=2))
            return True
        except requests.exceptions.RequestException as e:
            print(f"Registration failed: {e}")
            return False
    
    def issue_credential(self, message):
        '''Issue a verifiable credential with a message'''
        if not self.jwk:
            print("No key available for signing")
            return None
        
        print(f"\nCreating verifiable credential with message: {message}")
        
        # Create a simple verifiable credential
        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": f"device:{self.device_id}",
            "issuanceDate": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "credentialSubject": {
                "id": f"device:{self.device_id}",
                "message": message,
                "deviceId": self.device_id
            }
        }
        
        # Proof options for signing
        options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": self.verification_method
        }
        
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
            return None
    
    def send_credential(self, message):
        '''Issue and send a credential to the manufacturer'''
        credential = self.issue_credential(message)
        
        if not credential:
            return False
        
        url = f'{self.base_url}/api/devices/{self.device_id}/verify-credential'
        payload = {
            'credential': json.loads(credential) if isinstance(credential, str) else credential
        }
        
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            print(f"Credential sent: {response.json()}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to send credential: {e}")
            return False

def main():
    print("=" * 60)
    print("Device Client with DIDKit EdDSA Keys")
    print("=" * 60)
    
    # Create a device instance
    test_id = 'DEVICE-001'
    device = DeviceClient(device_id=test_id)
    
    # Generate EdDSA key pair
    try:
        device.generate_key()
    except Exception as e:
        print(f"Error generating key: {e}")
        return
    
    print("\n" + "=" * 60)
    print("Registering Device with Manufacturer")
    print("=" * 60)
    
    # Register the device with manufacturer
    if not device.register():
        print("Failed to register device, exiting")
        return
    
    print("\n" + "=" * 60)
    print("Creating and Sending Credential")
    print("=" * 60)
    
    # Create and send a credential
    test_message = "Hello from " + test_id + ". This is a test message."
    device.send_credential(test_message)
    
    print("\n" + "=" * 60)
    print("Device operation completed!")
    print("=" * 60)

if __name__ == '__main__':
    main()