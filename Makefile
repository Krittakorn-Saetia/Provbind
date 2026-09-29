# ==============================================================================
# PROVBIND Sprint Orchestration Makefile (make demo)
# ==============================================================================

# Variables
RUN_DIR ?= ./run
PYTHON  ?= python3

.PHONY: all setup test demo clean verify

# Default target
all: test

# ------------------------------------------------------------------------------
# 1. SETUP: Prepare run directories and environment
# ------------------------------------------------------------------------------
setup:
	@echo "📁 Setting up run directory at $(RUN_DIR)..."
	@mkdir -p $(RUN_DIR)
	@mkdir -p $(RUN_DIR)/envelopes
	@mkdir -p $(RUN_DIR)/log
	@echo "✅ Setup complete."

# ------------------------------------------------------------------------------
# 2. TEST: Run unit tests and validate schema contracts
# ------------------------------------------------------------------------------
test: setup
	@echo "🧪 Running Role 4 unit tests and contract validation..."
	@$(PYTHON) alerts/score.py
	@$(PYTHON) contracts/check_contracts.py $(RUN_DIR)
	@echo "🎉 All pre-flight tests passed!"

# ------------------------------------------------------------------------------
# 3. DEMO: Complete 5-Step End-to-End PROVBIND Evaluation Scenario
# ------------------------------------------------------------------------------
demo: setup
	@echo "======================================================================"
	@echo "🚀 STARTING PROVBIND END-TO-END LIVE DEMONSTRATION"
	@echo "======================================================================"
	@echo ""

	@# Step 1: Deploy & Bind (Admission Watcher & Cosign Signature Verification)
	@echo "----------------------------------------------------------------------"
	@echo "📌 STEP 1: Pod Admission, Cosign Verification & Envelope Compilation"
	@echo "----------------------------------------------------------------------"
	@$(PYTHON) controller/watch.py --mock --run $(RUN_DIR)
	@echo ""

	@# Step 2: Benign Execution Simulation
	@echo "----------------------------------------------------------------------"
	@echo "📌 STEP 2: Executing Benign Container Activity (ls /)"
	@echo "----------------------------------------------------------------------"
	@echo '{"id":"det-0001","time":"2026-09-28T10:00:00Z","container_id":"containerd://demo-app","namespace":"demo","pod":"demo-app-7d9f","container":"app","image_digest":"sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff","pid":101,"ppid":100,"exe":"/usr/bin/ls","parent_exe":"/bin/sh","class":"D_exec","subclass":"outside_closure","clause":{"kind":"process_closure","path":"/usr/bin/ls","detail":"outside entrypoint closure"},"origin":"AUTHENTICATED","context":{"depth":null}}' >> $(RUN_DIR)/detections.jsonl
	@PYTHONPATH=. $(PYTHON) alerts/run.py --run $(RUN_DIR) --once
	@echo ""

	@# Step 3: Attack Execution Simulation (Dropped Binary & Immutable Write)
	@echo "----------------------------------------------------------------------"
	@echo "📌 STEP 3: Simulating Supply-Chain Exploit (/tmp/.x9 & /etc/passwd write)"
	@echo "----------------------------------------------------------------------"
	@echo '{"id":"det-0002","time":"2026-09-28T10:01:00Z","container_id":"containerd://demo-app","namespace":"demo","pod":"demo-app-7d9f","container":"app","image_digest":"sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff","pid":201,"ppid":200,"exe":"/tmp/.x9","parent_exe":"/usr/local/bin/python3.11","class":"D_exec","subclass":"undeclared","clause":{"kind":"file_set","path":"/tmp/.x9","detail":"in no layer of attested image"},"origin":"AUTHENTICATED","context":{"depth":null}}' >> $(RUN_DIR)/detections.jsonl
	@echo '{"id":"det-0003","time":"2026-09-28T10:01:01Z","container_id":"containerd://demo-app","namespace":"demo","pod":"demo-app-7d9f","container":"app","image_digest":"sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff","pid":202,"ppid":200,"exe":"/etc/passwd","parent_exe":"/usr/local/bin/python3.11","class":"D_write","subclass":"declared_file","clause":{"kind":"immutable_file","path":"/etc/passwd","detail":"write intent to read-only image file"},"origin":"AUTHENTICATED","context":{"depth":null}}' >> $(RUN_DIR)/detections.jsonl
	@PYTHONPATH=. $(PYTHON) alerts/run.py --run $(RUN_DIR) --once
	@echo ""

	@# Display live color-coded alerts
	@$(PYTHON) alerts/show.py --run $(RUN_DIR)
	@echo ""

	@# Step 4: Merkle Log Tamper Demonstration
	@echo "----------------------------------------------------------------------"
	@echo "📌 STEP 4: Merkle Log Tamper-Evidence Check"
	@echo "----------------------------------------------------------------------"
	@$(PYTHON) alerts/verify_log.py $(RUN_DIR)
	@echo ""

	@# Step 5: Data Contract Compliance Check
	@echo "----------------------------------------------------------------------"
	@echo "📌 STEP 5: Validating Final Data Contracts Across Roles"
	@echo "----------------------------------------------------------------------"
	@$(PYTHON) contracts/check_contracts.py $(RUN_DIR)
	@echo ""
	@echo "======================================================================"
	@echo "🎉 PROVBIND LIVE DEMONSTRATION COMPLETED SUCCESSFULLY!"
	@echo "======================================================================"

# ------------------------------------------------------------------------------
# 4. VERIFY: Standalone Merkle log integrity audit
# ------------------------------------------------------------------------------
verify:
	@$(PYTHON) alerts/verify_log.py $(RUN_DIR)

# ------------------------------------------------------------------------------
# 5. CLEAN: Reset run directory and temporary logs
# ------------------------------------------------------------------------------
clean:
	@echo "🧹 Cleaning temporary run files..."
	@rm -rf $(RUN_DIR)
	@rm -rf ./test_run
	@echo "✨ Clean complete."
