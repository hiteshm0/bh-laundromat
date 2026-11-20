package laundromat.push

import rego.v1

default route := "static"

route := "block" if {
    input.category == "secret"
    input.rule != "aws-access-id"
}

route := "acknowledge" if input.category in {"dependency", "supply-chain"}

route := "runtime" if {
    input.category == "query"
    input.supported
    input.change != "pre-existing"
}

route := "triage" if {
    input.category in {"query", "command", "prompt", "guard"}
    not input.supported
    input.change != "pre-existing"
}
