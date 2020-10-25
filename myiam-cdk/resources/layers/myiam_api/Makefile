
BUILD_DIR = build
ZIP_FILENAME = layer.zip
MYIAM_API_PATH = ../../../../myiam-api
REQUIREMENTS_FILEPATH = requirements/requirements.prod.txt

$(BUILD_DIR)/$(ZIP_FILENAME):
	cd $(MYIAM_API_PATH) && mkdir -p $(BUILD_DIR)/python
	cd $(MYIAM_API_PATH) && pip3 install -r $(REQUIREMENTS_FILEPATH) -t $(BUILD_DIR)/python
	cd $(MYIAM_API_PATH)/$(BUILD_DIR) && zip -r $(ZIP_FILENAME) python
	mv $(MYIAM_API_PATH)/$(BUILD_DIR) .

clean:
	rm -rf $(BUILD_DIR)
