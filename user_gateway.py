# code for the user gateway

import requests # to make http requests
import json # to facilitate data transfer
import didkit # for verifiable credentials
from datetime import datetime, timezone # for timestamps
import secrets # for generating secure random challenges

class GatewayClient:
    def __init__(self, gateway_id, base_url='http://localhost:5000'):
        self.gateway_id = gateway_id
        self.base_url = base_url
        self.jwk = didkit.generateEd25519Key()
        self.did = didkit.keyToDID("key", self.jwk)
        self.credentials = []  # Wallet to store credentials
        self.current_challenge = None  # Store current challenge for verification

        print(f"\n{'='*60}")
        print(f"📱 Gateway {self.gateway_id} initialised")
        print(f"{'='*60}")
        print(f"Gateway DID: {self.did}")

    def generate_challenge(self):
        '''Generate a cryptographic challenge (nonce) for authentication'''
        print("\n" + "=" * 60)
        print("Generating authentication challenge...")
        print("=" * 60)

        # Generate a 32-byte random challenge
        challenge_bytes = secrets.token_bytes(32)
        challenge_hex = challenge_bytes.hex()

        self.current_challenge = challenge_hex
        print(f"✓ Challenge generated: {challenge_hex[:16]}...")

        return challenge_hex

    def challenge_device(self, device_id, device_url='http://localhost:6000'):
        '''Send a challenge directly to the device for VP generation'''
        print("\n" + "=" * 60)
        print(f"Sending challenge to device {device_id}...")
        print("=" * 60)

        if not self.current_challenge:
            print("✗ No challenge available. Generate a challenge first.")
            return False

        # Send directly to device's server endpoint (not through factory)
        url = f'{device_url}/challenge'
        payload = {
            'challenge': self.current_challenge,
            'gateway_did': self.did
        }

        print(f"Connecting to device at {url}...")

        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            response_data = response.json()

            print(f"✓ Challenge sent successfully")

            # Get VP from response
            vp = response_data.get('verifiable_presentation')
            if vp:
                print(f"✓ Received verifiable presentation from device")
                return self.verify_presentation(vp, device_id)
            else:
                print(f"✗ No verifiable presentation in response")
                return False

        except requests.exceptions.RequestException as e:
            print(f"✗ Failure in challenge/reponse: {e}")
            print(f"   Make sure the device server is running on {device_url}")
            print(f"   Check errors in device output")
            return False

    def verify_presentation(self, vp, device_id):
        '''Verify a verifiable presentation from the device'''
        print("\n" + "=" * 60)
        print(f"Verifying presentation from device {device_id}...")
        print("=" * 60)

        try:
            # Check that the challenge is in the proof (not in the VP body)
            vp_proof = vp.get('proof', {})
            vp_challenge = vp_proof.get('challenge')

            if vp_challenge != self.current_challenge:
                print(f"✗ Challenge mismatch!")
                print(f"   Expected: {self.current_challenge[:16]}...")
                print(f"   Received: {vp_challenge[:16] if vp_challenge else 'None'}...")
                return False

            print(f"✓ Challenge matches")

            # Verify the VP cryptographically using DIDKit
            # DIDKit will also verify the challenge in the proof
            verify_options = json.dumps({
                "proofPurpose": "authentication",
                "challenge": self.current_challenge
            })

            verification_result = didkit.verifyPresentation(
                json.dumps(vp),
                verify_options
            )

            result_dict = json.loads(verification_result)

            if len(result_dict.get('errors', [])) == 0:
                print(f"✓ Verifiable presentation verified successfully!")
                print(f"   Holder: {vp.get('holder')}")
                print(f"   Credentials included: {len(vp.get('verifiableCredential', []))}")

                # Clear the challenge after successful verification
                self.current_challenge = None

                return True
            else:
                print(f"✗ Presentation verification failed:")
                for error in result_dict.get('errors', []):
                    print(f"   - {error}")
                return False

        except Exception as e:
            print(f"✗ Error verifying presentation: {e}")
            return False

"""
def receive_credential(self, credential):
    #Store a credential in the device's wallet
    self.credentials.append(credential)
    print(f"\n📱 Device {self.device_id}: Credential received and stored")
    print(f"   Issuer: {credential.get('issuer')}")
    print(f"   Type: {credential.get('type')}")

    def generate_credential(self):
        gateway_credential_unsigned = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            #device_context
        ],
        "type": ["VerifiableCredential", "GatewayCredential"],
        "issuer": manufacturer_did,
        "issuanceDate": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "credentialSubject": {
            #credentialSubject.id
            "id": did,
            #"deviceId": device_id,
            #"status": "active"
        }
    }
        
    proof_options = {
        "proofPurpose": "assertionMethod",
        "verificationMethod": manufacturer_verification_method
    }

    try:
        signed_credential = didkit.issueCredential(
            json.dumps(gateway_credential_unsigned),
            json.dumps(proof_options),
            manufacturer_jwk
        )
        manufacturer_credential = json.loads(signed_manufacturer_credential)
        print(f"✓ Manufacturer self-signed credential issued")
        #print(f"  {manufacturer_credential}")
    except Exception as e:
        print(f"✗ Error issuing manufacturer credential: {e}")
        manufacturer_credential = None
    print("=" * 50 + "\n")    
"""



# Stage 2.1: Send challenge to device

# Stage 2.3: Send Authentication Status to Device
#  Receives VP (Verifiable Presentation)
#  Checks VP
#  Sends result

def main():
    print("*" * 60)
    print("User Gateway Client")
    print("*" * 60)

    # Create a gateway instance
    gateway_id = 'GATEWAY-001'
    device_test_id = 'DEVICE-001'
    gateway = GatewayClient(gateway_id=gateway_id)
    print(f"{gateway_id} initialised.")

    # Step 1: Generate challenge for device
    try:
        if not gateway.generate_challenge():
            print("Failed to generate challenge, exiting")
            return
    except Exception as e:
        print(f"Error during challenge generation: {e}")
        return

    # Step 2: Send challenge to device (device must be running!)
    try:
        if not gateway.challenge_device(device_test_id):
            print("Failed to authenticate device, exiting")
            return
    except Exception as e:
        print(f"Error during challenge send: {e}")
        return

    print("\n" + "=" * 60)
    print("Device authentication completed successfully!")
    print("=" * 60)

if __name__ == '__main__':
    main()