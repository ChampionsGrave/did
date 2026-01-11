
from datetime import datetime
from pyopenbadges.crypto import generate_keypair
from pyopenbadges.models import Profile, Achievement, OpenBadgeCredential, AchievementSubject
#from pyopenbadges.models.profile import Image
keypair = generate_keypair("RSA")
private_key = keypair.private_key
public_key = keypair.public_key
from pyopenbadges.crypto import load_keypair, load_public_key

# Sauvegarder la paire de clés
keypair.save("issuer_prikey.json", "issuer_pubkey.json")

# Charger la paire de clés (privée + publique)
#keypair = load_keypair("issuer_keys.json")

# Ou charger uniquement la clé publique
#public_key = load_public_key("issuer_keys.json")

# Creating a minimal issuer profile
issuer_minimal = Profile(
    id="http://localhost/issuers/1",
    type="Profile",
    name="Beans Inc."
)

from pyopenbadges.models import Achievement, Profile
from pyopenbadges.models.achievement import Criteria, Alignment

# Create an issuer first (required)
issuer = Profile(
    id="http://localhost/issuers/1",
    type="Profile",
    name="Beans Inc."
)

from pyopenbadges.models import OpenBadgeCredential, AchievementSubject, Evidence
from datetime import datetime, timedelta

# Badge issuance date
issuance_date = datetime.now()
# Expiration date (optional)
expiration_date = issuance_date + timedelta(days=365)

# Creating a minimal credential
# issuer = Profile(
#     id="https://example.org/issuers/1",
#     type="Profile",
#     name="Organisation Exemple"
# )

# 3. Créer un badge
badge = Achievement(
    id="https://example.org/badges/1",
    type="Achievement",
    name="Badge Exemple",
    description="Un badge d'exemple pour le tutoriel",
    issuer=issuer
)

# 4. Créer un credential
credential = OpenBadgeCredential(
    id="https://example.org/credentials/1",
    type=["VerifiableCredential", "OpenBadgeCredential"],
    issuer=issuer,
    issuanceDate=datetime.now(),
    credentialSubject=AchievementSubject(
        id="did:example:recipient",
        type="AchievementSubject",
        achievement=badge
    ),
    expirationDate=expiration_date
)

# 5. Signer le credential
signed_credential = credential.sign(
    private_key=keypair.private_key,
    verification_method="https://example.org/issuers/1/keys/1"
)

# 6. Vérifier la signature
is_valid = signed_credential.verify_signature(
    public_key=keypair.public_key
)

print(f"Le credential est authentique : {is_valid}")

# 7. Convertir en JSON-LD pour l'interopérabilité
json_ld = signed_credential.to_json_ld()

print(json_ld)
import jwt
print("\n \n \n")
encoded = jwt.encode(json_ld, private_key._key_obj, algorithm="PS256")
decoded = jwt.decode(encoded, public_key._key_obj, algorithms=["PS256"])

print(decoded)

print("\n\n\n")

print(encoded)

# decode = jwt.decode(encoded, key, algorithms="HS256")

# #-----------------------
# from pyopenbadges.utils.validators import (
#     validate_profile,
#     validate_achievement,
#     validate_credential,
#     validate_endorsement
# )
# Validating a Profile
# profile_validation = validate_profile(issuer_minimal)
# if profile_validation.is_valid:
#     print("The profile is valid according to the OpenBadge v3 specification")
# else:
#     print("Profile validation errors:", profile_validation.errors)

# # Validating an Achievement
# achievement_validation = validate_achievement(badge_minimal)
# if achievement_validation.is_valid:
#     print("The badge is valid according to the OpenBadge v3 specification")
# else:
#     print("Badge validation errors:", achievement_validation.errors)

# # Validating an OpenBadgeCredential
# credential_validation = validate_credential(credential_complete)
# if credential_validation.is_valid:
#     print("The credential is valid according to the OpenBadge v3 specification")
# else:
#     print("Credential validation errors:", credential_validation.errors)

# # You can also validate objects from JSON-LD dictionaries
# json_data = {
#     "id": "https://example.org/badges/2",
#     "type": "Achievement",
#     "name": "Python Intermediate Badge",
#     "issuer": "https://example.org/issuers/1"
# }
# validation_result = validate_achievement(json_data)
# print(f"JSON validation: {validation_result.is_valid}")

# from pyopenbadges.utils.serializers import (
#     save_object_to_file,
#     load_object_from_file,
#     json_ld_to_profile,
#     json_ld_to_achievement,
#     json_ld_to_credential,
#     json_ld_to_endorsement
# )

# # Save an object to a file
# save_object_to_file(credential_minimal, "credential.json")

# # Load an object from a file
# loaded_credential = load_object_from_file("credential.json", "OpenBadgeCredential")

# # Converting JSON-LD to Python objects
# profile_json_ld = {
#     "@context": "https://w3id.org/openbadges/v3",
#     "id": "https://example.org/issuers/2",
#     "type": "Profile",
#     "name": "Another Organization"
# }
# profile_obj = json_ld_to_profile(profile_json_ld)

# achievement_json_ld = {
#     "@context": "https://w3id.org/openbadges/v3",
#     "id": "https://example.org/badges/2",
#     "type": "Achievement",
#     "name": "Python Intermediate Badge",
#     "issuer": "https://example.org/issuers/1"
# }
# achievement_obj = json_ld_to_achievement(achievement_json_ld)

# from pyopenbadges.models import EndorsementCredential
# from pyopenbadges.models.endorsement import EndorsementSubject

# # Creating a profile for the endorsing organization
# endorser = Profile(
#     id="https://endorser.org/profiles/1",
#     type="Profile",
#     name="Accreditation Organization",
#     description="Organization that accredits quality badges"
# )

# # Creating an endorsement for a badge
# badge_endorsement = EndorsementCredential(
#     id="https://endorser.org/endorsements/1",
#     type=["VerifiableCredential", "EndorsementCredential"],
#     name="Python Beginner Badge Endorsement",
#     description="This badge is recognized by our organization as being of high quality",
#     issuer=endorser,
#     issuanceDate=datetime.now(),
#     credentialSubject=EndorsementSubject(
#         id="https://example.org/badges/1",
#         type="Achievement",
#         endorsementComment="This badge follows all good pedagogical practices and corresponds well to the beginner level in Python."
#     )
# )

# # Creating an endorsement for an issuer
# issuer_endorsement = EndorsementCredential(
#     id="https://endorser.org/endorsements/2",
#     type=["VerifiableCredential", "EndorsementCredential"],
#     name="My Organization Endorsement",
#     issuer=endorser,
#     issuanceDate=datetime.now(),
#     credentialSubject=EndorsementSubject(
#         id="https://example.org/issuers/1",
#         type="Profile",
#         endorsementComment="This issuer is recognized for the quality of its certification programs."
#     )
# )

# # Conversion to JSON-LD
# endorsement_json = badge_endorsement.to_json_ld()
# print(endorsement_json)