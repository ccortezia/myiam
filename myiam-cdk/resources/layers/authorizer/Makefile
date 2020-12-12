
BUILD_DIR = build
ZIP_FILENAME = layer.zip
REQUIREMENTS_FILEPATH = ./requirements.txt

$(BUILD_DIR)/$(ZIP_FILENAME):
	mkdir -p $(BUILD_DIR)/python
	pip3 install -r $(REQUIREMENTS_FILEPATH) -t $(BUILD_DIR)/python
	cd $(BUILD_DIR) && zip -r $(ZIP_FILENAME) python

clean:
	rm -rf $(BUILD_DIR)
