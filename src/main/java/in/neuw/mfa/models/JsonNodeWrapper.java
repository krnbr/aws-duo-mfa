package in.neuw.mfa.models;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JsonNodeWrapper {

    private JsonNode node;
    private boolean isPresent;

}
