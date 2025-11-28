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
        self.manufacturer_credential = None  # Credential issued by manufacturer
        
    def generate_key(self):
        '''Generate an EdDSA key pair using DIDKit'''
        print("Generating EdDSA key pair for "+self.device_id+"...")
        
        # Generate a new Ed25519 key
        self.jwk = didkit.generateEd25519Key()
        jwk_dict = json.loads(self.jwk)
        
        # Debug: print the full key (be careful - this includes private key!)
        print(f"\nFull JWK generated:")
        print(json.dumps(jwk_dict, indent=2))
        
        # Get the DID from the key
        self.did = didkit.keyToDID("key", self.jwk)
        print(f"DID: {self.did}")
        
        # Get the verification method
        self.verification_method = didkit.keyToVerificationMethod("key", self.jwk)
        
        print(f"\nKey generated successfully!")
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
            'use': jwk_dict.get('use')  # Optional but good to include
        }
             
        url = f'{self.base_url}/api/devices/register'
        payload = {
            'device_id': self.device_id,
            'public_key_jwk': public_key,
            'did': self.did,
            'verification_method': self.verification_method
        }
        
        # Debug: print what we're sending
        print(f"\nPayload being sent:")
        print(json.dumps(payload, indent=2))
        
        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            response_data = response.json()
            
            print(f"\nDevice registered successfully!")
            
            # this needs to move sooner
            # Store the manufacturer's credential
            self.manufacturer_credential = response_data.get('credential')
            
            if self.manufacturer_credential:
                print(f"\n✓ Received credential from manufacturer!")
                print(f"Credential type: {self.manufacturer_credential.get('type')}")
                print(f"Issuer: {self.manufacturer_credential.get('issuer')}")
                print(f"Subject: {self.manufacturer_credential.get('credentialSubject', {}).get('id')}")
                
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
            
            print(f"\nFull registration response:")
            print(json.dumps(response_data, indent=2))
            return True
        except requests.exceptions.RequestException as e:
            print(f"Registration failed: {e}")
            return False
    
    def issue_credential(self, message):
        '''Self-issue a verifiable credential with a message'''
        if not self.jwk:
            print("No key available for signing")
            return None
        
        print(f"\nDEBUG: Full JWK before signing:")
        print(self.jwk)
        
        print(f"\nCreating verifiable credential with message: {message}")
        
        # Create a simple verifiable credential
        # Use the DID as the issuer (not a custom device: prefix)
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
        
        print(f"Credential to sign:")
        print(json.dumps(credential, indent=2))
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
            'message': message  # Send message separately
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
    
    # First, let's check what functions are available
    #print("\nAvailable DIDKit functions:")
    #print([func for func in dir(didkit) if not func.startswith('_')])
    #print()
    
    # Create a device instance
    device = DeviceClient(device_id='DEVICE-001')
    
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
    test_message = "Hello from DEVICE-001. This is a test for PoC."
    device.send_credential(test_message)
    
    print("\n" + "=" * 60)
    print("Device operation completed!")
    print("=" * 60)

if __name__ == '__main__':
    main()