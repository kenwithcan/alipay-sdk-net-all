/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = AlipaySDKNet.OpenAPI.Client.OpenAPIDateConverter;

namespace AlipaySDKNet.OpenAPI.Model
{
    /// <summary>
    /// DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse
    /// </summary>
    [JsonConverter(typeof(DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponseJsonConverter))]
    [DataContract(Name = "datadigital_fincloud_generalsaas_ocr_server_detect_default_response")]
    public partial class DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse : AbstractOpenAPISchema, IEquatable<DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse" /> class
        /// with the <see cref="CommonErrorType" /> class
        /// </summary>
        /// <param name="actualInstance">An instance of CommonErrorType.</param>
        public DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse(CommonErrorType actualInstance)
        {
            this.IsNullable = false;
            this.SchemaType= "anyOf";
            this.ActualInstance = actualInstance ?? throw new ArgumentException("Invalid instance found. Must not be null.");
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse" /> class
        /// with the <see cref="DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel" /> class
        /// </summary>
        /// <param name="actualInstance">An instance of DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel.</param>
        public DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse(DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel actualInstance)
        {
            this.IsNullable = false;
            this.SchemaType= "anyOf";
            this.ActualInstance = actualInstance ?? throw new ArgumentException("Invalid instance found. Must not be null.");
        }


        private Object _actualInstance;

        /// <summary>
        /// Gets or Sets ActualInstance
        /// </summary>
        public override Object ActualInstance
        {
            get
            {
                return _actualInstance;
            }
            set
            {
                if (value.GetType() == typeof(CommonErrorType))
                {
                    this._actualInstance = value;
                }
                else if (value.GetType() == typeof(DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel))
                {
                    this._actualInstance = value;
                }
                else
                {
                    throw new ArgumentException("Invalid instance found. Must be the following types: CommonErrorType, DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel");
                }
            }
        }

        /// <summary>
        /// Get the actual instance of `CommonErrorType`. If the actual instance is not `CommonErrorType`,
        /// the InvalidClassException will be thrown
        /// </summary>
        /// <returns>An instance of CommonErrorType</returns>
        public CommonErrorType GetCommonErrorType()
        {
            return (CommonErrorType)this.ActualInstance;
        }

        /// <summary>
        /// Get the actual instance of `DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel`. If the actual instance is not `DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel`,
        /// the InvalidClassException will be thrown
        /// </summary>
        /// <returns>An instance of DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel</returns>
        public DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel GetDatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel()
        {
            return (DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel)this.ActualInstance;
        }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse {\n");
            sb.Append("  ActualInstance: ").Append(this.ActualInstance).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public override string ToJson()
        {
            return JsonConvert.SerializeObject(this.ActualInstance, DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse.SerializerSettings);
        }

        /// <summary>
        /// Converts the JSON string into an instance of DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse
        /// </summary>
        /// <param name="jsonString">JSON string</param>
        /// <returns>An instance of DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse</returns>
        public static DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse FromJson(string jsonString)
        {
            DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse newDatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse = null;

            if (string.IsNullOrEmpty(jsonString))
            {
                return newDatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse;
            }

            try
            {
                newDatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse = new DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse(JsonConvert.DeserializeObject<CommonErrorType>(jsonString, DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse.SerializerSettings));
                // deserialization is considered successful at this point if no exception has been thrown.
                return newDatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse;
            }
            catch (Exception exception)
            {
                // deserialization failed, try the next one
                System.Diagnostics.Debug.WriteLine(string.Format("Failed to deserialize `{0}` into CommonErrorType: {1}", jsonString, exception.ToString()));
            }

            try
            {
                newDatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse = new DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse(JsonConvert.DeserializeObject<DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel>(jsonString, DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse.SerializerSettings));
                // deserialization is considered successful at this point if no exception has been thrown.
                return newDatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse;
            }
            catch (Exception exception)
            {
                // deserialization failed, try the next one
                System.Diagnostics.Debug.WriteLine(string.Format("Failed to deserialize `{0}` into DatadigitalFincloudGeneralsaasOcrServerDetectErrorResponseModel: {1}", jsonString, exception.ToString()));
            }

            // no match found, throw an exception
            throw new InvalidDataException("The JSON string `" + jsonString + "` cannot be deserialized into any schema defined.");
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse);
        }

        /// <summary>
        /// Returns true if DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse instances are equal
        /// </summary>
        /// <param name="input">Instance of DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse input)
        {
            if (input == null)
                return false;

            return this.ActualInstance.Equals(input.ActualInstance);
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                if (this.ActualInstance != null)
                    hashCode = hashCode * 59 + this.ActualInstance.GetHashCode();
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> IValidatableObject.Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

    /// <summary>
    /// Custom JSON converter for DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse
    /// </summary>
    public class DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponseJsonConverter : JsonConverter
    {
        /// <summary>
        /// To write the JSON string
        /// </summary>
        /// <param name="writer">JSON writer</param>
        /// <param name="value">Object to be converted into a JSON string</param>
        /// <param name="serializer">JSON Serializer</param>
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            writer.WriteRawValue((string)(typeof(DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse).GetMethod("ToJson").Invoke(value, null)));
        }

        /// <summary>
        /// To convert a JSON string into an object
        /// </summary>
        /// <param name="reader">JSON reader</param>
        /// <param name="objectType">Object type</param>
        /// <param name="existingValue">Existing value</param>
        /// <param name="serializer">JSON Serializer</param>
        /// <returns>The object converted from the JSON string</returns>
        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if(reader.TokenType != JsonToken.Null)
            {
                return DatadigitalFincloudGeneralsaasOcrServerDetectDefaultResponse.FromJson(JObject.Load(reader).ToString(Formatting.None));
            }
            return null;
        }

        /// <summary>
        /// Check if the object can be converted
        /// </summary>
        /// <param name="objectType">Object type</param>
        /// <returns>True if the object can be converted</returns>
        public override bool CanConvert(Type objectType)
        {
            return false;
        }
    }

}
