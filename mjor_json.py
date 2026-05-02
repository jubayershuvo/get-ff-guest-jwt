# majorResExtractJson.py
# -*- coding: utf-8 -*-
import json
import base64
from typing import Dict, Any, Optional
import MajorLoginRes_pb2

def extract_major_login_res_from_protobuf(protobuf_data: bytes) -> Optional[Dict[str, Any]]:
    """
    Parse MajorLoginRes from protobuf bytes and return as JSON
    
    Args:
        protobuf_data: Raw protobuf bytes from the response
        
    Returns:
        Dictionary containing the parsed MajorLoginRes data
    """
    try:
        # Create protobuf message instance
        major_login_res = MajorLoginRes_pb2.MajorLoginRes()
        
        # Parse the protobuf data
        major_login_res.ParseFromString(protobuf_data)
        
        # Convert to dictionary
        result = protobuf_to_dict(major_login_res)
        
        return result
        
    except Exception as e:
        print(f"Error parsing protobuf: {e}")
        return None


def protobuf_to_dict(message) -> Dict[str, Any]:
    """
    Recursively convert protobuf message to dictionary
    """
    result = {}
    
    # Get all fields from the message
    for field, value in message.ListFields():
        field_name = field.name
        
        # Handle repeated fields (lists)
        if field.label == field.LABEL_REPEATED:
            result[field_name] = [protobuf_to_dict(item) if hasattr(item, 'ListFields') else item for item in value]
        
        # Handle nested messages
        elif hasattr(value, 'ListFields'):
            result[field_name] = protobuf_to_dict(value)
        
        # Handle bytes (convert to base64 for JSON serialization or hex)
        elif isinstance(value, bytes):
            # Option 1: Convert to base64 string
            result[field_name] = base64.b64encode(value).decode('ascii')
            # Option 2: Convert to hex string (uncomment if preferred)
            # result[field_name] = value.hex()
        
        # Handle basic types
        else:
            result[field_name] = value
    
    return result


def extract_from_http_response(response_content: bytes) -> Optional[Dict[str, Any]]:
    """
    Extract MajorLoginRes from HTTP response body (protobuf format)
    
    Args:
        response_content: Raw response body bytes from HTTP request
        
    Returns:
        Dictionary containing the parsed MajorLoginRes data
    """
    return extract_major_login_res_from_protobuf(response_content)


def convert_to_serializable_json(data: Dict[str, Any]) -> str:
    """
    Convert the parsed data to JSON-serializable format
    Handles non-serializable types like bytes
    """
    def json_converter(obj):
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('ascii')
        return str(obj)
    
    return json.dumps(data, indent=2, default=json_converter, ensure_ascii=False)


# Example usage with the protobuf definition
def main():
    """
    Main function to read protobuf data from stdin or file and output JSON
    """
    import sys
    
    # Read binary data
    if len(sys.argv) > 1:
        # Read from file
        with open(sys.argv[1], 'rb') as f:
            protobuf_data = f.read()
    else:
        # Read from stdin (binary)
        protobuf_data = sys.stdin.buffer.read()
    
    # Parse the protobuf data
    result = extract_major_login_res_from_protobuf(protobuf_data)
    
    if result:
        # Output as JSON
        print(convert_to_serializable_json(result))
    else:
        print(json.dumps({"error": "Failed to parse MajorLoginRes from protobuf data"}, indent=2))
        sys.exit(1)
