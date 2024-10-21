all: secap int constants

secap: secap.p4
	@./bmv2-compile.sh "secap" ""

int: int.p4
	@./bmv2-compile.sh "int" "-DTARGET_BMV2"

constants:
	docker run -v $(ONOS_ROOT):/onos -w /onos/tools/dev/bin \
		--entrypoint ./onos-gen-p4-constants opennetworking/p4mn:stable \
		-o /onos/pipelines/secap/src/main/java/org/onosproject/pipelines/secap/SecapConstants.java \
		secap /onos/pipelines/secap/src/main/resources/p4c-out/bmv2/secap_p4info.txt

clean:
	rm -rf p4c-out/bmv2/*
