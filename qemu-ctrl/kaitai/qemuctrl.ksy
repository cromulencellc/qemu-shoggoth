meta:
  id: comms_message
  title: QEMU Job System Message
  endian: le
seq:
  - id: header
    type: comms_message_header
  - id: msg
    type:
      switch-on: header.msg_id
      cases:
        'message_enum::msg_request_config': comms_request_config_msg
        'message_enum::msg_request_rst': comms_request_rapid_save_tree_msg
        'message_enum::msg_request_job_add': comms_request_job_add_msg
        'message_enum::msg_request_job_purge': comms_request_job_purge_msg
        'message_enum::msg_request_job_report': comms_request_job_report_msg
        'message_enum::msg_request_quit': comms_request_quit_msg
        'message_enum::msg_response_config': comms_response_config_msg
        'message_enum::msg_response_report': comms_response_job_report_msg
        'message_enum::msg_response_rst': comms_response_rapid_save_tree_msg
enums:
  memory_enum:
    1: memory_virtual
    2: memory_physical
  message_enum:
    11: msg_request_config
    12: msg_request_rst
    13: msg_request_job_add
    14: msg_request_job_purge
    15: msg_request_job_report
    16: msg_request_quit
    20: msg_response_config
    21: msg_response_report
    22: msg_response_rst
  job_report_enum:
    1: job_report_processor
    2: job_report_register
    4: job_report_virtual_memory
    8: job_report_physical_memory
    16: job_report_all_physical_memory
    32: job_report_all_virtual_memory
    64: job_report_error
    128: job_report_exception
  job_add_enum:
    31: job_add_register
    32: job_add_memory
    33: job_add_exit_insn_count
    34: job_add_exit_insn_range
    35: job_add_exit_exception
    36: job_add_timeout
    37: job_add_stream
  purge_action_enum:
    61: purge_drop_results
    62: purge_send_results
  quit_action_enum:
    71: quit_clean
    72: quit_now
    73: quit_kill
types:
  name_type:
    seq:
      - encoding: ASCII
        type: str
        size: 15
  sha1_hash:
    seq:
      - size: 20
  job_report_type:
    seq:
      - id: job_report_exception
        type: b1
      - id: job_report_error
        type: b1
      - id: job_report_all_virtual_memory
        type: b1
      - id: job_report_all_physical_memory
        type: b1
      - id: job_report_physical_memory
        type: b1
      - id: job_report_virtual_memory
        type: b1
      - id: job_report_register
        type: b1
      - id: job_report_processor
        type: b1
  config_valid_settings:
    seq:
      - id: config_job_reserved6
        type: b1
      - id: config_job_reserved5
        type: b1
      - id: config_job_reserved4
        type: b1
      - id: config_job_reserved3
        type: b1
      - id: config_job_reserved2
        type: b1
      - id: config_job_reserved1
        type: b1
      - id: config_job_timeout_mask
        type: b1
      - id: config_job_report_mask
        type: b1
  comms_message_header:
    seq:
      - id: msg_id
        type: u1
        enum: message_enum
        doc: Message identifier.
      - id: version
        type: u1
        doc: Reserved for future releases.
      - id: has_next_message
        type: u1
        doc: Denotes a fragmented message.
      - id: reserved1
        type: u1
      - id: reserved2
        type: u4
      - id: size
        type: u8
    doc: Total size of message including the header.
  comms_request_config_msg:
    seq:
      - id: queue
        type: u1
        doc: Target queue.
      - id: report_mask
        type: job_report_type
        doc: Items to report upon job completion.
      - id: reserved1
        type: u2
      - id: reserved2
        type: u4
      - id: valid_settings
        type: config_valid_settings
        doc: Denotes valid fields in this message.
      - id: timeout
        type: u8
        doc: Items to report upon job completion.
  comms_response_config_msg:
    seq:
      - id: queue
        type: u1
        doc: Target queue.
      - id: report_mask
        type: job_report_type
        doc: Items reported upon job completion.
      - id: reserved1
        type: u2
      - id: reserved2
        type: u4
      - id: timeout
        type: u8
        doc: Items to report upon job completion.
  comms_response_job_report_msg:
    seq:
      - id: queue
        type: u1
        doc: Target queue.
      - id: reserved1
        type: u1
      - id: reserved2
        type: u2
      - id: job_id
        type: s4
      - id: num_insns
        type: u8
      - id: job_hash
        type: sha1_hash
      - id: entries
        type: job_report_entry
        repeat: eos
    types:
      comms_response_job_report_processor_entry:
        seq:
          - id: reserved1
            type: u1
          - id: reserved2
            type: u2
          - id: reserved3
            type: u4
          - id: reserved4
            type: u4
          - id: cpu_name
            type: name_type
          - id: cpu_id
            type: u1
      comms_response_job_report_register_entry:
        seq:
          - id: id
            type: u1
          - id: register_size
            type: u1
          - id: reserved1
            type: u1
          - id: reserved2
            type: u4
          - id: name
            type: name_type
          - id: value
            size: register_size
      comms_response_job_report_memory_entry:
        seq:
          - id: reserved1
            type: u1
          - id: reserved2
            type: u2
          - id: memory_size
            type: u4
          - id: offset
            type: u8
          - id: reserved3
            type: u4
          - id: reserved4
            type: u2
          - id: reserved5
            type: u1
          - id: value
            size: memory_size
      comms_response_job_report_error_entry:
        seq:
          - id: reserved1
            type: u1
          - id: reserved2
            type: u2
          - id: error_id
            type: u4
          - id: error_text
            type: str
            size: 24
            encoding: ASCII
          - id: error_loc
            type: u8
      comms_response_job_report_exception_entry:
        seq:
          - id: reserved1
            type: u1
          - id: reserved2
            type: u2
          - id: reserved3
            type: u4
          - id: exception_mask
            type: u8
      job_report_entry:
        seq:
          - id: entry_type
            type: u1
            enum: job_report_enum
          - id: item
            type:
              switch-on: entry_type
              cases:
                'job_report_enum::job_report_processor': comms_response_job_report_processor_entry
                'job_report_enum::job_report_register': comms_response_job_report_register_entry
                'job_report_enum::job_report_virtual_memory': comms_response_job_report_memory_entry
                'job_report_enum::job_report_physical_memory': comms_response_job_report_memory_entry
                'job_report_enum::job_report_all_physical_memory': comms_response_job_report_memory_entry
                'job_report_enum::job_report_all_virtual_memory': comms_response_job_report_memory_entry
                'job_report_enum::job_report_error': comms_response_job_report_error_entry
                'job_report_enum::job_report_exception': comms_response_job_report_exception_entry
  comms_request_job_add_msg:
    seq:
      - id: queue
        type: u1
        doc: Target queue.
      - id: cont_job
        type: u1
      - id: reserved1
        type: u2
      - id: job_id
        type: s4
      - id: base_hash
        type: sha1_hash
      - id: entries
        type: job_add_entry
        repeat: eos
    types:
      comms_request_job_add_register_setup:
        seq:
          - id: id
            type: u1
          - id: register_size
            type: u2
          - id: name
            type: name_type
          - id: value
            size: register_size
      comms_request_job_add_memory_setup:
        seq:
          - id: flags
            type: u1
            enum: memory_enum
          - id: reserved1
            type: u2
          - id: memsize
            type: u4
          - id: offset
            type: u8
          - id: reserved2
            type: u1
          - id: reserved3
            type: u1
          - id: reserved4
            type: u1
          - id: value
            size: memsize
      comms_request_job_add_exit_insn_count_constraint:
        seq:
          - id: reserved1
            type: u1
          - id: reserved2
            type: u2
          - id: reserved3
            type: u4
          - id: insn_limit
            type: u8
      comms_request_job_add_exit_insn_range_constraint:
        seq:
          - id: reserved1
            type: u1
          - id: reserved2
            type: u2
          - id: block_size
            type: u4
          - id: offset
            type: u8
      comms_request_job_add_exit_exception_constraint:
        seq:
          - id: reserved1
            type: u1
          - id: reserved2
            type: u2
          - id: reserved3
            type: u4
          - id: mask
            type: u8
      comms_request_job_add_timeout_setup:
        seq:
          - id: reserved1
            type: u1
          - id: reserved2
            type: u2
          - id: reserved3
            type: u4
          - id: timeout
            type: u8
      comms_request_job_add_stream_setup:
        seq:
          - id: reserved1
            type: u1
          - id: reserved2
            type: u2
          - id: fileno
            type: u4
          - id: strsize
            type: u4
          - id: reserved3
            type: u2
          - id: reserved4
            type: u1
          - id: value
            size: strsize
      job_add_entry:
        seq:
          - id: entry_type
            type: u1
            enum: job_add_enum
          - id: item
            type:
              switch-on: entry_type
              cases:
                'job_add_enum::job_add_register': comms_request_job_add_register_setup
                'job_add_enum::job_add_memory': comms_request_job_add_memory_setup
                'job_add_enum::job_add_exit_insn_count': comms_request_job_add_exit_insn_count_constraint
                'job_add_enum::job_add_exit_insn_range': comms_request_job_add_exit_insn_range_constraint
                'job_add_enum::job_add_exit_exception': comms_request_job_add_exit_exception_constraint
                'job_add_enum::job_add_timeout': comms_request_job_add_timeout_setup
                'job_add_enum::job_add_stream': comms_request_job_add_stream_setup
  comms_request_job_purge_msg:
    seq:
      - id: queue
        type: u1
      - id: action
        type: u1
        enum: purge_action_enum
  comms_request_job_report_msg:
    seq:
      - id: queue
        type: u1
      - id: report_mask
        type: job_report_type
        doc: Items to report for completed job.
      - id: reserved1
        type: u2
      - id: job_id
        type: s4
      - id: job_hash
        type: sha1_hash
  comms_request_quit_msg:
    seq:
      - id: queue
        type: u1
        enum: quit_action_enum
  comms_request_rapid_save_tree_msg:
    seq:
      - id: queue
        type: u1
      - id: reserved1
        type: u1
      - id: reserved2
        type: u2
      - id: job_id
        type: s4
  comms_response_rapid_save_tree_msg:
    seq:
      - id: queue
        type: u1
      - id: reserved1
        type: u1
      - id: reserved2
        type: u2
      - id: job_id
        type: s4
      - id: num_insns
        type: u8
      - id: tree_insns
        type: comms_response_rapid_save_tree_instruction_entry
        size: num_insns
    types:
      comms_response_rapid_save_tree_instruction_entry:
        seq:
          - id: label
            type: str
            size: 24
            encoding: ASCII
          - id: num_nodes
            type: u8
          - id: tree_nodes
            type: comms_response_rapid_save_tree_node_header
            size: num_nodes
        types:
          comms_response_rapid_save_tree_node_header:
            seq:
              - id: index_offset
                type: u4
              - id: state_offset
                type: u4
              - id: job_id
                type: s4
              - id: num_indices
                type: u4
              - id: timestamp
                type: s8
              - id: instruction_number
                type: u8
              - id: cpu_exception_index
                type: u8
              - id: node_indices
                type: comms_response_rapid_save_tree_node_index
                size: num_indices
              - id: node_state
                type: comms_response_rapid_save_tree_node_state
            types:
              comms_response_rapid_save_tree_node_index:
                seq:
                  - id: label
                    type: str
                    size: 32
                    encoding: ASCII
                  - id: instance_id
                    type: u4
                  - id: section_id
                    type: u4
                  - id: offset
                    type: u8
              comms_response_rapid_save_tree_node_state:
                seq:
                  - id: state_size
                    type: u4
                  - id: reserved1
                    type: u2
                  - id: reserved2
                    type: u1
                  - id: state
                    size: state_size
instances:
  sizeof_comms_message:
    value: sizeof<comms_message_header>
