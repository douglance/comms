use comms_interactions::{
    AgentIdentity, QuestionChoice, QuestionRecord, QuestionRequest, QuestionState,
    SlackDestination, slack_message_payload,
};
use std::collections::HashSet;

#[test]
fn choice_buttons_have_distinct_action_ids() {
    let record = QuestionRecord {
        id: "q_fixture".into(),
        agent: AgentIdentity {
            agent_id: "agent_fixture".into(),
            label: None,
        },
        request: QuestionRequest {
            text: "Ship the build?".into(),
            destination: SlackDestination {
                channel: "D_FIXTURE".into(),
                thread_ts: None,
            },
            blocks: None,
            choices: vec![
                QuestionChoice {
                    id: "yes".into(),
                    text: "Ship".into(),
                    value: None,
                },
                QuestionChoice {
                    id: "no".into(),
                    text: "Hold".into(),
                    value: None,
                },
            ],
            deadline_seconds: None,
            no_deadline: true,
        },
        state: QuestionState::PendingDelivery,
        created_at: 100,
        updated_at: 100,
        deadline_at: None,
        message: None,
        answer: None,
        cancelled_at: None,
        cancel_reason: None,
    };
    let payload = slack_message_payload(&record);
    let actions = payload["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|block| block["type"] == "actions")
        .unwrap();
    let elements = actions["elements"].as_array().unwrap();
    assert_eq!(elements.len(), 2);
    let ids: HashSet<_> = elements
        .iter()
        .map(|element| element["action_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids.len(),
        2,
        "Slack requires distinct action IDs within a block"
    );
}
