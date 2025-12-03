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
        #self.manufacturer_credential = None  # Credential issued by manufacturer
        self.manufacturer_public_key = None  # Manufacturer's public key for verification
        self.registration_jwk = None # keypair used to register future keys
        self.registration_did = None
        self.registration_verification_method = None
        self.jwk = None # keypair used for general authentication
        self.did = None
        self.verification_method = None
        self.verifiable_credential = None
        
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
            self.verification_method = response_data.get('verification_method')

            # Extract manufacturer information
            manufacturer_public_key_dict = response_data.get('manufacturer_public_key')
            self.manufacturer_public_key = json.dumps(manufacturer_public_key_dict)
            #self.manufacturer_credential = response_data.get('credential')#HHHHH

            print(f"  ✓ Received long-term registration keypair")
            print(f"     Registration key: {self.registration_jwk}")
            print(f"     Registration public key (x): {registration_jwk_dict.get('x')}")
            print(f"     Registration DID: {self.registration_did}")
            print(f"     Verification method: {self.verification_method}")
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
    
    def register(self):
        '''Register this device with the manufacturer, sending public key'''
        print("\n" + "=" * 60)
        print(f"Registering {self.device_id}  with manufacturer...")
        print("=" * 60)

        if not self.registration_jwk:
            print("No key available, must provision from factory first")
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

        url = f'{self.base_url}/api/devices/register'
        payload = {
            'device_id': self.device_id,
            'public_key_jwk': public_key,
            'did': self.did,
            'verification_method': verification_method
        }

        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            response_data = response.json()
            
            print(f"\nDevice registered successfully!")
            
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
    print("\n" + "=" * 60)
    print("Registering public key with Manufacturer")
    print("=" * 60)
    
    if not device.register():
        print("Failed to register device, exiting")
        return
    """
    # Create and send a credential
    print("\n" + "=" * 60)

    print("Creating and Sending Credential")
    print("=" * 60)
    
    test_message = "Hello from DEVICE-001. This is a test for PoC."
    #device.send_credential(test_message)
    
    # Done
    print("\n" + "=" * 60)
    print("Device registration completed!")
    print("=" * 60)
    """

if __name__ == '__main__':
    main()