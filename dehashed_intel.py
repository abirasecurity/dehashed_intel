def _save_entries_to_csv(entries: List[Dict], output_path: str) -> None:
    """Save search result entries to a CSV file with improved formatting."""
    if not entries:
        return

    # Determine all possible fields from all entries
    all_fields = set()
    for entry in entries:
        all_fields.update(entry.keys())

    # Remove 'raw_record' if present as it's typically a nested structure
    if 'raw_record' in all_fields:
        all_fields.remove('raw_record')

    # Prioritize important fields first, then add the rest alphabetically
    priority_fields = ['id', 'email', 'username', 'password', 'hashed_password', 
                      'name', 'address', 'phone', 'ip_address', 'database_name']

    # Create ordered fieldnames list
    fieldnames = []
    for field in priority_fields:
        if field in all_fields:
            fieldnames.append(field)
            all_fields.remove(field)

    # Add remaining fields alphabetically
    fieldnames.extend(sorted(list(all_fields)))

    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for entry in entries:
            # Handle list fields by joining them with commas
            row_data = {}
            for field in fieldnames:
                if field in entry:
                    if isinstance(entry[field], list):
                        row_data[field] = ', '.join(str(item) for item in entry[field])
                    else:
                        row_data[field] = entry[field]
                else:
                    row_data[field] = ''

            writer.writerow(row_data)
