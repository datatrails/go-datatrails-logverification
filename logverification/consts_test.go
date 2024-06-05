package logverification

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
)
