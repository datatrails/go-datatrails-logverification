package app

/**
 * Defines constants only used in testing.
 */

const (
	testEventJson = `
	{
		"identity": "assets/9ccdc19b-44a1-434c-afab-14f8eac3405c/events/82c9f5c2-fe77-4885-86aa-417f654d3b2f",
		"asset_identity": "assets/9ccdc19b-44a1-434c-afab-14f8eac3405c",
		"event_attributes": {
			"1": "pour flour and milk into bowl",
			"2": "mix together until gloopy",
			"3": "slowly add in the sugar while still mixing",
			"4": "finally add in the eggs",
			"5": "put in the over until golden brown"
		},
		"asset_attributes": {},
		"operation": "Record",
		"behaviour": "RecordEvidence",
		"timestamp_declared": "2024-01-24T11:42:16Z",
		"timestamp_accepted": "2024-01-24T11:42:16Z",
		"timestamp_committed": "2024-01-24T11:42:17.121Z",
		"principal_declared": {
			"issuer": "cupcake-world",
			"subject": "chris the cupcake connoisseur",
			"display_name": "chris",
			"email": "chris@example.com"
		},
		"principal_accepted": {
			"issuer": "https://app.dev-user-0.dev.datatrails.ai/appidpv1",
			"subject": "924c9054-c342-47a3-a7b8-8c0bfedd37a3",
			"display_name": "API",
			"email": ""
		},
		"confirmation_status": "COMMITTED",
		"transaction_id": "",
		"block_number": 0,
		"transaction_index": 0,
		"from": "0xc98130dc7b292FB485F842785f6F63A520a404A5",
		"tenant_identity": "tenant/15c551cf-40ed-4cdb-a94b-142d6e3c620a",
		"merklelog_entry": {
			"commit": {
				"index": 53,
				"idtimestamp": "0x018d3b472e22146400"
			}
		}
	}
	`

	logVersion0Event = `
	{
  "identity": "assets/899e00a2-29bc-4316-bf70-121ce2044472/events/450dce94-065e-4f6a-bf69-7b59f28716b6",
  "asset_identity": "assets/899e00a2-29bc-4316-bf70-121ce2044472",
  "event_attributes": {},
  "asset_attributes": {
    "arc_display_name": "Default asset",
    "default": "true",
    "arc_description": "Collection for Events not specifically associated with any specific Asset"
  },
  "operation": "NewAsset",
  "behaviour": "AssetCreator",
  "timestamp_declared": "2025-01-16T16:12:38Z",
  "timestamp_accepted": "2025-01-16T16:12:38Z",
  "timestamp_committed": "2025-01-16T16:12:38.576970217Z",
  "principal_declared": {
    "issuer": "https://accounts.google.com",
    "subject": "105632894023856861149",
    "display_name": "Henry SocialTest",
    "email": "henry.socialtest@gmail.com"
  },
  "principal_accepted": {
    "issuer": "https://accounts.google.com",
    "subject": "105632894023856861149",
    "display_name": "Henry SocialTest",
    "email": "henry.socialtest@gmail.com"
  },
  "confirmation_status": "CONFIRMED",
  "transaction_id": "",
  "block_number": 0,
  "transaction_index": 0,
  "from": "0x412bB2Ecd6f2bDf26D64de834Fa17167192F4c0d",
  "tenant_identity": "tenant/112758ce-a8cb-4924-8df8-fcba1e31f8b0",
  "merklelog_entry": {
    "commit": {
      "index": "0",
      "idtimestamp": "01946fe35fc6017900"
    },
    "confirm": {
      "mmr_size": "1",
      "root": "YecBKn8UtUZ6hlTnrnXIlKvNOZKuMCIemNdNA8wOyjk=",
      "timestamp": "1737043961154",
      "idtimestamp": "",
      "signed_tree_head": ""
    },
    "unequivocal": null
  }
}
	`

	logVersion1Event = `
	{
  "identity": "events/01947000-3456-780f-bfa9-29881e3bac88",
  "attributes": {
    "foo": "bar"
  },
  "trails": [],
  "origin_tenant": "tenant/112758ce-a8cb-4924-8df8-fcba1e31f8b0",
  "created_by": "2ef471c2-f997-4503-94c8-60b5c929a3c3",
  "created_at": 1737045849174,
  "confirmation_status": "CONFIRMED",
  "merklelog_commit": {
    "index": "1",
    "idtimestamp": "019470003611017900"
  }
}
	`
)
