import boto3
import json
import subprocess

# Initialize AWS EC2 Client
client = boto3.client("ec2")

# Fetch Security Groups
security_groups_response = client.describe_security_groups()
security_groups = security_groups_response["SecurityGroups"]

# Fetch Instances
instances_response = client.describe_instances()
reservations = instances_response["Reservations"]

# Convert security groups into a dictionary
sg_rules = {}
for sg in security_groups:
    sg_id = sg["GroupId"]
    sg_name = sg["GroupName"]
    ip_permissions = sg["IpPermissions"]
    sg_rules[sg_id] = {"name": sg_name, "rules": ip_permissions}

# Generate a separate Graphviz image for each instance
for reservation in reservations:
    for instance in reservation["Instances"]:
        instance_id = instance["InstanceId"]
        instance_sgs = instance["SecurityGroups"]  # List of security groups for this instance
        instance_tags = instance.get("Tags", [])  # Tags list

        # Extract instance name from tags
        instance_name = "Unknown"
        for tag in instance_tags:
            if tag["Key"] == "Name":
                instance_name = tag["Value"]
                break

        # Start Graphviz DOT file content
        dot_content = [
            f'digraph "{instance_id}" {{',
            'rankdir=LR;',
            'node [fontsize=14, penwidth=2];',
            'edge [fontsize=14, penwidth=3];'
        ]

        # Instance Node with Name
        dot_content.append(f'"{instance_id}" [shape=ellipse, style=filled, fillcolor=lightblue, label="Instance: {instance_name}\\n{instance_id}"];')

        # Process each security group attached to this instance
        for sg in instance_sgs:
            sg_id = sg["GroupId"]
            sg_name = sg_rules.get(sg_id, {}).get("name", "Unknown SG")

            # Add Security Group Node
            dot_content.append(f'"{sg_id}" [shape=box, style=filled, fillcolor=lightgray, label="SG: {sg_name}\\n{sg_id}"];')

            # Link Security Group to Instance
            dot_content.append(f'"{sg_id}" -> "{instance_id}" [label="Attached to", color=black, penwidth=2, fontsize=14];')

            # Process inbound rules for this security group
            for rule in sg_rules.get(sg_id, {}).get("rules", []):
                from_port = rule.get("FromPort", "Any")
                to_port = rule.get("ToPort", "Any")
                protocol = rule.get("IpProtocol", "Any")

                # Process all sources
                for ip_range in rule.get("IpRanges", []):
                    source = ip_range.get("CidrIp", "Unknown")
                    is_open = source == "0.0.0.0/0"
                    color = "red" if is_open else "black"
                    font_color = "red" if is_open else "black"

                    dot_content.append(
                        f'"{source}" -> "{sg_id}" [label="Port: {from_port}-{to_port} ({protocol})", '
                        f'color={color}, fontcolor={font_color}, penwidth=3, fontsize=14];'
                    )

                for ipv6_range in rule.get("Ipv6Ranges", []):
                    source = ipv6_range.get("CidrIpv6", "Unknown")
                    is_open = source == "::/0"
                    color = "red" if is_open else "black"
                    font_color = "red" if is_open else "black"

                    dot_content.append(
                        f'"{source}" -> "{sg_id}" [label="Port: {from_port}-{to_port} ({protocol})", '
                        f'color={color}, fontcolor={font_color}, penwidth=3, fontsize=14];'
                    )

                for user_id_group_pair in rule.get("UserIdGroupPairs", []):
                    source_sg = user_id_group_pair.get("GroupId", "Unknown")
                    dot_content.append(
                        f'"{source_sg}" -> "{sg_id}" [label="Port: {from_port}-{to_port} ({protocol})", '
                        f'color=black, penwidth=3, fontsize=14];'
                    )

        # Close DOT file content
        dot_content.append("}")

        # Write DOT file
        dot_filename = f"{instance_id}.dot"
        with open(dot_filename, "w") as f:
            f.write("\n".join(dot_content))

        # Generate PNG using Graphviz
        output_image = f"{instance_name.replace(' ', '_')}_{instance_id}.png"
        subprocess.run(["dot", "-Tpng", dot_filename, "-o", output_image])

        print(f"AWS Security visualization saved for {instance_name} ({instance_id}) as {output_image}")
