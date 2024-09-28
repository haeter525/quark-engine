import json
from pathlib import Path
from typing import List, Literal, Set, TypedDict
from langchain_core.messages import (
    BaseMessage,
    SystemMessage,
    HumanMessage,
    AIMessage,
)
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from pydantic import BaseModel, Field

from prompts import (
    ASK_SUGGESTION,
    SUGGESTION_NOT_IN_LIST,
    INTRODUCE_ALL_DETECTION_STEPS,
)

DetectionStep = str


class DetectionStepSuggestion:
    class Suggestions(BaseModel):
        steps: List[DetectionStep] = Field(
            description="A list of suggested detection steps"
        )

    class AgentState(TypedDict):
        # The current chain of the detection steps
        stepChain: List[DetectionStep]

        # The chat history with the llm
        messageHistory: List[BaseMessage]

        # The next detection steps suggested by the llm
        suggestions: Set[DetectionStep]

    def __init__(self) -> None:
        self.__toolList = self.__loadToolList()
        self.__autoCompletionLLM = self.__createLLM()
        self.__workflow = self.__createWorkflow()
        self.__maxTry = 3

    def __loadToolList(self) -> List[DetectionStep]:
        jsonObj = json.loads(
            Path("toolJson/toolList.json").read_text(
                encoding="utf-8"
            )
        )
        return [stepObj["title"] for stepObj in jsonObj["QuarkScriptTools"]]

    def __createLLM(self):
        llm = ChatOpenAI(
            name="Detection Step Suggestions LLM",
            model="gpt-4o-mini",
            temperature=0.2,
        ).with_structured_output(schema=DetectionStepSuggestion.Suggestions)

        llmWithToolList = (
            lambda messages: [
                SystemMessage(
                    INTRODUCE_ALL_DETECTION_STEPS.format(
                        toolList=", ".join(self.__toolList)
                    ),
                )
            ]
            + messages
        ) | llm

        return llmWithToolList

    def __createWorkflow(self) -> StateGraph:

        def generateSuggestion(state: DetectionStepSuggestion.AgentState):
            """Ask the LLM for suggestions or a revision of the suggestions
            provided previously.

            :param state: The state of the LLM, storing the chat history and
            the suggestions (if any)
            :return: The updated state, storing the prompt sent in this
            function and the response received from the LLM
            """
            messages = state.get("messageHistory", [])

            if len(messages) != 0:
                # The LLM has suggested the detection steps,
                # but some don't exist.
                prompt = HumanMessage(
                    SUGGESTION_NOT_IN_LIST.format(
                        suggestedSteps=state.get("suggestedSteps")
                    )
                )

            else:
                # Ask the LLM to suggest the detection steps.
                prompt = HumanMessage(
                    ASK_SUGGESTION.format(stepChain=state.get("stepChain"))
                )

            # Add the prompt to the chat history
            messages.append(prompt)

            # Prompt the LLM with the chat history
            suggestions = set(self.__autoCompletionLLM.invoke(messages).steps)

            # Add the received suggestions to the history
            messages.append(AIMessage(str(suggestions)))

            return {"messageHistory": messages, "suggestions": suggestions}

        def checkSuggestions(
            state: DetectionStepSuggestion.AgentState,
        ) -> Literal["Valid", "Invalid"]:
            """Check if the suggested detection steps are valid or have been
            revised `maxTry` times.

            :return: "Valid" if all suggested detection steps are valid or have
            been revised `maxTry` times, otherwise "Invalid"
            """
            rawSuggestions = list(state.get("suggestions", []))

            isValid = all(step in self.__toolList for step in rawSuggestions)

            if (
                len(state.get("messageHistory", [])) > (self.__maxTry * 2)
            ) or isValid:
                # We have valid suggestions or have tried for 3 times.
                return "Valid"
            else:
                return "Invalid"

        def fillInvalidSuggestions(state: DetectionStepSuggestion.AgentState):
            """Remove the invalid detection steps.

            :param state: The state of the LLM, storing the chat history and
            the suggestions (if any)
            :return: The updated state, storing only the chat history and the
            valid suggestions (if any)
            """
            rawSuggestions = list(state.get("suggestions", []))

            valid = [
                step for step in rawSuggestions if step in self.__toolList
            ]

            return {"suggestions": valid}

        workflow = StateGraph(DetectionStepSuggestion.AgentState)

        workflow.add_node("generate_suggestions", generateSuggestion)
        workflow.add_node("fill_invalid_suggestions", fillInvalidSuggestions)

        workflow.set_entry_point("generate_suggestions")

        workflow.add_conditional_edges(
            source="generate_suggestions",
            path=checkSuggestions,
            path_map={
                "Valid": "fill_invalid_suggestions",
                "Invalid": "generate_suggestions",
            },
        )
        workflow.add_edge("fill_invalid_suggestions", END)

        return workflow.compile()

    def provideSuggestions(
        self, stepChain: List[DetectionStep], maxTry: int = 3
    ):
        self.__maxTry = maxTry

        state = self.__workflow.invoke({"stepChain": stepChain})

        return state["suggestions"]


if __name__ == "__main__":

    stepChain = [
        "init Rule Object",
        "run Quark Analysis",
        "run Quark Analysis",
        "get Caller Method",
        "get Parameter Values",
    ]

    print(f"The current detection steps are: \n\"{', '.join(stepChain)}\n")

    suggestions = DetectionStepSuggestion().provideSuggestions(stepChain=stepChain)
    print(f"The suggested next steps are: {', '.join(suggestions)}")
