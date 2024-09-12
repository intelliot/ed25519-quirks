<script>
/* eslint-env jquery */

import DataRow from '../components/DataRow.vue';
import SeedRow from '../components/SeedRow.vue';
import StatusSpan from '../components/StatusSpan.vue';
import withEncoding from '../mixins/withEncoding';

export default {
  components: {
    DataRow, SeedRow, StatusSpan,
  },
  mixins: [withEncoding],

  data() {
    return {
      signedMessage: '',
      signer: '',
      verifySignature: '',
    };
  },

  computed: {
    verification() {
      const binaryMessage = this.$Buffer.from(this.signedMessage, 'utf8');
      let verification;
      let signerParseError = false;
      let signatureParseError = false;
      let signerKey = null;
      let verifySignatureBytes = null;

      try {
        const buffer = this.$Buffer.from(this.signer, this.encoding);
        signerKey = this.$crypto.PublicKey.parse(buffer);
      } catch (e) {
        signerParseError = true;
      }

      try {
        verifySignatureBytes = this.$Buffer.from(this.verifySignature, this.encoding);
        if (signerKey != null) {
          // An error might occur here if the scalar has set upper bits.
          verification = signerKey.verification(binaryMessage, verifySignatureBytes);
        }
      } catch (e) {
        signatureParseError = true;
      }

      if (signerParseError || signatureParseError) {
        return {
          error: true,
          signerParseError,
          signatureParseError,
        };
      }

      return {
        error: verification.decompressionError(),
        decompressionError: verification.decompressionError(),
        hashScalar: verification.hashScalar(),
        computedPoint: verification.computedPoint(),
        success: verification.success(),
      };
    },
  },

  watch: {
    encoding(_, oldEncoding) {
      try {
        const parsedSigner = this.$Buffer.from(this.signer, oldEncoding);
        this.signer = this.repr(parsedSigner);
      } catch (e) {
        // Nothing we can do, unfortunately.
      }

      try {
        const parsedSignature = this.$Buffer.from(this.verifySignature, oldEncoding);
        this.verifySignature = this.repr(parsedSignature);
      } catch (e) {
        // Nothing we can do, unfortunately.
      }
    },
  },

  mounted() {
    const verifyButton = document.querySelector('#verification button');
    verifyButton.style.display = 'inline-block';
    verifyButton.addEventListener('click', (event) => {
      event.preventDefault();
      this.copyFromSigning();
    });
  },

  methods: {
    copyFromSigning() {
      this.signedMessage = this.message;
      this.signer = this.repr(this.keypair.publicKey().bytes());
      this.verifySignature = this.repr(this.signature.bytes());
    },
  },
};
</script>
