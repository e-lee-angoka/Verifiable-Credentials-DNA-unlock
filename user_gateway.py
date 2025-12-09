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
        self.manufacturer_id = None  # Trusted issuer DID (set during provisioning)
        self.manufacturer_did = None  # Trusted issuer DID (set during provisioning)

        print(f"\n{'='*60}")
        print(f"📱 Gateway {self.gateway_id} initialised")
        print(f"{'='*60}")
        #print(f"Gateway DID: {self.did}")

    def get_manufacturer_id(self):
        '''Request manufacturer ID from the factory'''
        print("\n" + "=" * 60)
        print("Getting issuer ID from manufacturer")
        print("=" * 60)

        url = f'{self.base_url}/api/gateways/provision'
        payload = {'gateway_id': self.gateway_id}

        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            response_data = response.json()

            # in practice this will be OOB so no need to cryptographically verify
            print(f"  ✓ Received response")
            # Extract manufacturer information
            self.manufacturer_id = response_data.get('manufacturer_id')
            self.manufacturer_did = response_data.get('manufacturer_did')

            print(f"  ✓ Received manufacturer information")
            print(f"     Manufacturer ID: {self.manufacturer_id}")
            print(f"     Manufacturer DID: {self.manufacturer_did}")
            print(f"     (Public key can be derived from DID)")

            return True
        except requests.exceptions.RequestException as e:
            print(f"  ✗ Provisioning failed: {e}")
            return False
        

    def challenge_device(self, device_id, device_url='http://localhost:6000'):
        '''Send a challenge directly to the device for VP generation'''
        print("\n" + "=" * 60)
        print(f"Sending challenge to device {device_id}...")
        print("=" * 60)

        challenge_bytes = secrets.token_bytes(32)
        challenge_hex = challenge_bytes.hex()

        self.current_challenge = challenge_hex
        print(f" Challenge generated: {challenge_hex[:16]}...")
        # Send directly to device's server endpoint (not through factory)
        url = f'{device_url}/challenge'
        payload = {
            'challenge': challenge_hex,
            'gateway_did': self.did
        }

        print(f" Connecting to device at {url}...")

        try:
            response = requests.post(url, json=payload)
            response.raise_for_status()
            response_data = response.json()

            print(f" ✓ Challenge sent successfully")

            # Get VP from response
            vp = response_data.get('verifiable_presentation')
            if vp:
                print(f" ✓ Received response with VP")
                return self.verify_presentation(vp, device_id) # HERE
            else:
                print(f" ✗ No verifiable presentation in response")
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
            
            print(f" Performing full verification...")
            verification_result = didkit.verifyPresentation(
                json.dumps(vp),
                verify_options
            )

            result_dict = json.loads(verification_result)

            if len(result_dict.get('errors', [])) == 0:
                print(f" ✓ Verifiable presentation verified successfully!")
                #print(f"   Holder: {vp.get('holder')}")
                print(f"   Credentials included: {len(vp.get('verifiableCredential', []))}")

                # Verify that the VC was issued by a trusted issuer
                vcs = vp.get('verifiableCredential', [])
                if not vcs:
                    print(f"✗ No credentials in presentation")
                    return False

                # Check each credential's issuer
                for i, vc in enumerate(vcs):
                    issuer = vc.get('issuer')
                    if issuer != self.manufacturer_did:
                        print(f"✗ Credential {i+1} from untrusted issuer!")
                        print(f"   Expected: {self.manufacturer_did}")
                        print(f"   Received: {issuer}")
                        return False

                print(f" ✓ All credentials from trusted manufacturer with DID {self.manufacturer_did}")

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


# Stage 2.3: Send Authentication Status to Device
#  Receives VP (Verifiable Presentation)
#  Checks VP
#  Sends result

def main():
    print("*" * 60)
    print("User Gateway Client")
    print("*" * 60)

    # Create a gateway instance
    gateway_test_id = 'GATEWAY-001'
    gateway = GatewayClient(gateway_id=gateway_test_id)

    # Step 1: Get manufacturer ID (trusted issuer)
    try:
        if not gateway.get_manufacturer_id():
            print("Failed to get manufacturer ID, exiting")
            return
    except Exception as e:
        print(f"Error during manufacturer provisioning: {e}")
        return

    # Step 2: Challenge device (device must be running!)
    try:
        if not gateway.challenge_device(device_test_id):
            print("Failed to authenticate device, exiting")
            return
    except Exception as e:
        print(f"Error during challenge send: {e}")
        return

    print("✓" * 5 + " Device authentication completed successfully! " + "✓" * 5)


if __name__ == '__main__':
    main()