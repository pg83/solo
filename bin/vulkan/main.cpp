#include <png.h>
#include "dlfcn.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vulkan/vulkan.h>

namespace {
    static constexpr uint32_t imageWidth = 512;
    static constexpr uint32_t imageHeight = 512;
    static constexpr VkDeviceSize imageSize = imageWidth * imageHeight * 4;

    alignas(4) static const uint32_t shaderCode[] = {
#include "shader.inc"
    };

    class Error {
    public:
        explicit Error(const char* message);
        Error(const char* operation, VkResult result);

        const char* message() const;

    private:
        char message_[512];
    };

    class Renderer {
    public:
        Renderer();
        ~Renderer();

        void render(const char* output);

    private:
        void createInstance();
        void selectPhysicalDevice();
        void createDevice();
        void createBuffer();
        void createPipeline();
        void dispatch();
        void writePng(const char* output);

        VkInstance instance_;
        VkPhysicalDevice physicalDevice_;
        VkDevice device_;
        VkQueue queue_;
        VkBuffer buffer_;
        VkDeviceMemory memory_;
        VkDescriptorSetLayout descriptorSetLayout_;
        VkDescriptorPool descriptorPool_;
        VkDescriptorSet descriptorSet_;
        VkShaderModule shaderModule_;
        VkPipelineLayout pipelineLayout_;
        VkPipeline pipeline_;
        VkCommandPool commandPool_;
        VkFence fence_;
        uint32_t queueFamily_;
        bool memoryCoherent_;
    };

    struct Options {
        const char* output;
        const char* driver;
    };
}

Error::Error(const char* message) {
    snprintf(message_, sizeof(message_), "%s", message);
}

Error::Error(const char* operation, VkResult result) {
    snprintf(message_, sizeof(message_), "%s failed: VkResult %d", operation, result);
}

const char* Error::message() const {
    return message_;
}

Renderer::Renderer()
    : instance_(VK_NULL_HANDLE)
    , physicalDevice_(VK_NULL_HANDLE)
    , device_(VK_NULL_HANDLE)
    , queue_(VK_NULL_HANDLE)
    , buffer_(VK_NULL_HANDLE)
    , memory_(VK_NULL_HANDLE)
    , descriptorSetLayout_(VK_NULL_HANDLE)
    , descriptorPool_(VK_NULL_HANDLE)
    , descriptorSet_(VK_NULL_HANDLE)
    , shaderModule_(VK_NULL_HANDLE)
    , pipelineLayout_(VK_NULL_HANDLE)
    , pipeline_(VK_NULL_HANDLE)
    , commandPool_(VK_NULL_HANDLE)
    , fence_(VK_NULL_HANDLE)
    , queueFamily_(UINT32_MAX)
    , memoryCoherent_(false)
{
}

Renderer::~Renderer() {
    if (device_ != VK_NULL_HANDLE) {
        if (fence_ != VK_NULL_HANDLE) {
            vkDestroyFence(device_, fence_, nullptr);
        }
        if (commandPool_ != VK_NULL_HANDLE) {
            vkDestroyCommandPool(device_, commandPool_, nullptr);
        }
        if (pipeline_ != VK_NULL_HANDLE) {
            vkDestroyPipeline(device_, pipeline_, nullptr);
        }
        if (pipelineLayout_ != VK_NULL_HANDLE) {
            vkDestroyPipelineLayout(device_, pipelineLayout_, nullptr);
        }
        if (shaderModule_ != VK_NULL_HANDLE) {
            vkDestroyShaderModule(device_, shaderModule_, nullptr);
        }
        if (descriptorPool_ != VK_NULL_HANDLE) {
            vkDestroyDescriptorPool(device_, descriptorPool_, nullptr);
        }
        if (descriptorSetLayout_ != VK_NULL_HANDLE) {
            vkDestroyDescriptorSetLayout(device_, descriptorSetLayout_, nullptr);
        }
        if (buffer_ != VK_NULL_HANDLE) {
            vkDestroyBuffer(device_, buffer_, nullptr);
        }
        if (memory_ != VK_NULL_HANDLE) {
            vkFreeMemory(device_, memory_, nullptr);
        }
        vkDestroyDevice(device_, nullptr);
    }
    if (instance_ != VK_NULL_HANDLE) {
        vkDestroyInstance(instance_, nullptr);
    }
}

void Renderer::render(const char* output) {
    createInstance();
    selectPhysicalDevice();
    createDevice();
    createBuffer();
    createPipeline();
    dispatch();
    writePng(output);
}

void Renderer::createInstance() {
    VkApplicationInfo application{};
    application.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    application.pApplicationName = "solo-vulkan";
    application.applicationVersion = VK_MAKE_API_VERSION(0, 1, 0, 0);
    application.pEngineName = "solo";
    application.engineVersion = VK_MAKE_API_VERSION(0, 1, 0, 0);
    application.apiVersion = VK_API_VERSION_1_0;

    VkInstanceCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &application;

    VkResult result = vkCreateInstance(&createInfo, nullptr, &instance_);
    if (result != VK_SUCCESS) {
        throw Error("vkCreateInstance", result);
    }
}

void Renderer::selectPhysicalDevice() {
    uint32_t deviceCount = 0;
    VkResult result = vkEnumeratePhysicalDevices(instance_, &deviceCount, nullptr);
    if (result != VK_SUCCESS) {
        throw Error("vkEnumeratePhysicalDevices", result);
    }
    if (deviceCount == 0) {
        throw Error("Vulkan loader found no physical devices");
    }

    auto* devices = static_cast<VkPhysicalDevice*>(calloc(deviceCount, sizeof(VkPhysicalDevice)));
    if (devices == nullptr) {
        throw Error("cannot allocate physical device list");
    }
    result = vkEnumeratePhysicalDevices(instance_, &deviceCount, devices);
    if (result != VK_SUCCESS) {
        free(devices);
        throw Error("vkEnumeratePhysicalDevices", result);
    }

    for (uint32_t deviceIndex = 0; deviceIndex < deviceCount && physicalDevice_ == VK_NULL_HANDLE; ++deviceIndex) {
        uint32_t familyCount = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(devices[deviceIndex], &familyCount, nullptr);
        auto* families = static_cast<VkQueueFamilyProperties*>(calloc(familyCount, sizeof(VkQueueFamilyProperties)));
        if (families == nullptr) {
            free(devices);
            throw Error("cannot allocate queue family list");
        }
        vkGetPhysicalDeviceQueueFamilyProperties(devices[deviceIndex], &familyCount, families);
        for (uint32_t familyIndex = 0; familyIndex < familyCount; ++familyIndex) {
            if ((families[familyIndex].queueFlags & VK_QUEUE_COMPUTE_BIT) != 0) {
                physicalDevice_ = devices[deviceIndex];
                queueFamily_ = familyIndex;
                break;
            }
        }
        free(families);
    }
    free(devices);

    if (physicalDevice_ == VK_NULL_HANDLE) {
        throw Error("no Vulkan device exposes a compute queue");
    }

    VkPhysicalDeviceProperties properties{};
    vkGetPhysicalDeviceProperties(physicalDevice_, &properties);
    printf("device: %s (Vulkan %u.%u.%u)\n", properties.deviceName, VK_API_VERSION_MAJOR(properties.apiVersion), VK_API_VERSION_MINOR(properties.apiVersion), VK_API_VERSION_PATCH(properties.apiVersion));
}

void Renderer::createDevice() {
    float priority = 1.0f;
    VkDeviceQueueCreateInfo queueInfo{};
    queueInfo.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    queueInfo.queueFamilyIndex = queueFamily_;
    queueInfo.queueCount = 1;
    queueInfo.pQueuePriorities = &priority;

    VkDeviceCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    createInfo.queueCreateInfoCount = 1;
    createInfo.pQueueCreateInfos = &queueInfo;

    VkResult result = vkCreateDevice(physicalDevice_, &createInfo, nullptr, &device_);
    if (result != VK_SUCCESS) {
        throw Error("vkCreateDevice", result);
    }
    vkGetDeviceQueue(device_, queueFamily_, 0, &queue_);
}

void Renderer::createBuffer() {
    VkBufferCreateInfo bufferInfo{};
    bufferInfo.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO;
    bufferInfo.size = imageSize;
    bufferInfo.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    bufferInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

    VkResult result = vkCreateBuffer(device_, &bufferInfo, nullptr, &buffer_);
    if (result != VK_SUCCESS) {
        throw Error("vkCreateBuffer", result);
    }

    VkMemoryRequirements requirements{};
    vkGetBufferMemoryRequirements(device_, buffer_, &requirements);
    VkPhysicalDeviceMemoryProperties properties{};
    vkGetPhysicalDeviceMemoryProperties(physicalDevice_, &properties);

    uint32_t memoryType = UINT32_MAX;
    for (uint32_t index = 0; index < properties.memoryTypeCount; ++index) {
        VkMemoryPropertyFlags flags = properties.memoryTypes[index].propertyFlags;
        if ((requirements.memoryTypeBits & (1u << index)) != 0 && (flags & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) != 0) {
            if (memoryType == UINT32_MAX || (flags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) != 0) {
                memoryType = index;
                memoryCoherent_ = (flags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) != 0;
            }
            if (memoryCoherent_) {
                break;
            }
        }
    }
    if (memoryType == UINT32_MAX) {
        throw Error("no host-visible Vulkan memory type is available");
    }

    VkMemoryAllocateInfo allocationInfo{};
    allocationInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocationInfo.allocationSize = requirements.size;
    allocationInfo.memoryTypeIndex = memoryType;
    result = vkAllocateMemory(device_, &allocationInfo, nullptr, &memory_);
    if (result != VK_SUCCESS) {
        throw Error("vkAllocateMemory", result);
    }
    result = vkBindBufferMemory(device_, buffer_, memory_, 0);
    if (result != VK_SUCCESS) {
        throw Error("vkBindBufferMemory", result);
    }
}

void Renderer::createPipeline() {
    VkDescriptorSetLayoutBinding binding{};
    binding.binding = 0;
    binding.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    binding.descriptorCount = 1;
    binding.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;

    VkDescriptorSetLayoutCreateInfo descriptorLayoutInfo{};
    descriptorLayoutInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    descriptorLayoutInfo.bindingCount = 1;
    descriptorLayoutInfo.pBindings = &binding;
    VkResult result = vkCreateDescriptorSetLayout(device_, &descriptorLayoutInfo, nullptr, &descriptorSetLayout_);
    if (result != VK_SUCCESS) {
        throw Error("vkCreateDescriptorSetLayout", result);
    }

    VkDescriptorPoolSize poolSize{};
    poolSize.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    poolSize.descriptorCount = 1;
    VkDescriptorPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    poolInfo.maxSets = 1;
    poolInfo.poolSizeCount = 1;
    poolInfo.pPoolSizes = &poolSize;
    result = vkCreateDescriptorPool(device_, &poolInfo, nullptr, &descriptorPool_);
    if (result != VK_SUCCESS) {
        throw Error("vkCreateDescriptorPool", result);
    }

    VkDescriptorSetAllocateInfo setInfo{};
    setInfo.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO;
    setInfo.descriptorPool = descriptorPool_;
    setInfo.descriptorSetCount = 1;
    setInfo.pSetLayouts = &descriptorSetLayout_;
    result = vkAllocateDescriptorSets(device_, &setInfo, &descriptorSet_);
    if (result != VK_SUCCESS) {
        throw Error("vkAllocateDescriptorSets", result);
    }

    VkDescriptorBufferInfo bufferInfo{};
    bufferInfo.buffer = buffer_;
    bufferInfo.range = imageSize;
    VkWriteDescriptorSet write{};
    write.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
    write.dstSet = descriptorSet_;
    write.dstBinding = 0;
    write.descriptorCount = 1;
    write.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    write.pBufferInfo = &bufferInfo;
    vkUpdateDescriptorSets(device_, 1, &write, 0, nullptr);

    VkShaderModuleCreateInfo shaderInfo{};
    shaderInfo.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    shaderInfo.codeSize = sizeof(shaderCode);
    shaderInfo.pCode = shaderCode;
    result = vkCreateShaderModule(device_, &shaderInfo, nullptr, &shaderModule_);
    if (result != VK_SUCCESS) {
        throw Error("vkCreateShaderModule", result);
    }

    VkPushConstantRange pushConstants{};
    pushConstants.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    pushConstants.size = sizeof(uint32_t) * 2;
    VkPipelineLayoutCreateInfo pipelineLayoutInfo{};
    pipelineLayoutInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO;
    pipelineLayoutInfo.setLayoutCount = 1;
    pipelineLayoutInfo.pSetLayouts = &descriptorSetLayout_;
    pipelineLayoutInfo.pushConstantRangeCount = 1;
    pipelineLayoutInfo.pPushConstantRanges = &pushConstants;
    result = vkCreatePipelineLayout(device_, &pipelineLayoutInfo, nullptr, &pipelineLayout_);
    if (result != VK_SUCCESS) {
        throw Error("vkCreatePipelineLayout", result);
    }

    VkPipelineShaderStageCreateInfo stageInfo{};
    stageInfo.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stageInfo.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stageInfo.module = shaderModule_;
    stageInfo.pName = "main";
    VkComputePipelineCreateInfo pipelineInfo{};
    pipelineInfo.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipelineInfo.stage = stageInfo;
    pipelineInfo.layout = pipelineLayout_;
    result = vkCreateComputePipelines(device_, VK_NULL_HANDLE, 1, &pipelineInfo, nullptr, &pipeline_);
    if (result != VK_SUCCESS) {
        throw Error("vkCreateComputePipelines", result);
    }
}

void Renderer::dispatch() {
    VkCommandPoolCreateInfo poolInfo{};
    poolInfo.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO;
    poolInfo.queueFamilyIndex = queueFamily_;
    VkResult result = vkCreateCommandPool(device_, &poolInfo, nullptr, &commandPool_);
    if (result != VK_SUCCESS) {
        throw Error("vkCreateCommandPool", result);
    }

    VkCommandBufferAllocateInfo allocationInfo{};
    allocationInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    allocationInfo.commandPool = commandPool_;
    allocationInfo.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    allocationInfo.commandBufferCount = 1;
    VkCommandBuffer commandBuffer = VK_NULL_HANDLE;
    result = vkAllocateCommandBuffers(device_, &allocationInfo, &commandBuffer);
    if (result != VK_SUCCESS) {
        throw Error("vkAllocateCommandBuffers", result);
    }

    VkCommandBufferBeginInfo beginInfo{};
    beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    result = vkBeginCommandBuffer(commandBuffer, &beginInfo);
    if (result != VK_SUCCESS) {
        throw Error("vkBeginCommandBuffer", result);
    }
    vkCmdBindPipeline(commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_);
    vkCmdBindDescriptorSets(commandBuffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipelineLayout_, 0, 1, &descriptorSet_, 0, nullptr);
    const uint32_t parameters[] = {imageWidth, imageHeight};
    vkCmdPushConstants(commandBuffer, pipelineLayout_, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(parameters), parameters);
    vkCmdDispatch(commandBuffer, (imageWidth + 7) / 8, (imageHeight + 7) / 8, 1);

    VkBufferMemoryBarrier barrier{};
    barrier.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER;
    barrier.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT;
    barrier.dstAccessMask = VK_ACCESS_HOST_READ_BIT;
    barrier.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    barrier.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    barrier.buffer = buffer_;
    barrier.size = VK_WHOLE_SIZE;
    vkCmdPipelineBarrier(commandBuffer, VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 0, nullptr, 1, &barrier, 0, nullptr);
    result = vkEndCommandBuffer(commandBuffer);
    if (result != VK_SUCCESS) {
        throw Error("vkEndCommandBuffer", result);
    }

    VkFenceCreateInfo fenceInfo{};
    fenceInfo.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    result = vkCreateFence(device_, &fenceInfo, nullptr, &fence_);
    if (result != VK_SUCCESS) {
        throw Error("vkCreateFence", result);
    }
    VkSubmitInfo submitInfo{};
    submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    submitInfo.commandBufferCount = 1;
    submitInfo.pCommandBuffers = &commandBuffer;
    result = vkQueueSubmit(queue_, 1, &submitInfo, fence_);
    if (result != VK_SUCCESS) {
        throw Error("vkQueueSubmit", result);
    }
    result = vkWaitForFences(device_, 1, &fence_, VK_TRUE, UINT64_MAX);
    if (result != VK_SUCCESS) {
        throw Error("vkWaitForFences", result);
    }
}

void Renderer::writePng(const char* output) {
    void* pixels = nullptr;
    VkResult result = vkMapMemory(device_, memory_, 0, VK_WHOLE_SIZE, 0, &pixels);
    if (result != VK_SUCCESS) {
        throw Error("vkMapMemory", result);
    }
    if (!memoryCoherent_) {
        VkMappedMemoryRange range{};
        range.sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE;
        range.memory = memory_;
        range.size = VK_WHOLE_SIZE;
        result = vkInvalidateMappedMemoryRanges(device_, 1, &range);
        if (result != VK_SUCCESS) {
            vkUnmapMemory(device_, memory_);
            throw Error("vkInvalidateMappedMemoryRanges", result);
        }
    }

    png_image image{};
    image.version = PNG_IMAGE_VERSION;
    image.width = imageWidth;
    image.height = imageHeight;
    image.format = PNG_FORMAT_RGBA;
    if (png_image_write_to_file(&image, output, 0, pixels, 0, nullptr) == 0) {
        Error error(image.message);
        png_image_free(&image);
        vkUnmapMemory(device_, memory_);
        throw error;
    }
    png_image_free(&image);

    uint64_t checksum = 1469598103934665603ull;
    const auto* bytes = static_cast<const unsigned char*>(pixels);
    for (VkDeviceSize index = 0; index < imageSize; ++index) {
        checksum = (checksum ^ bytes[index]) * 1099511628211ull;
    }
    vkUnmapMemory(device_, memory_);
    printf("wrote %s (%ux%u, checksum %016llx)\n", output, imageWidth, imageHeight, static_cast<unsigned long long>(checksum));
}

namespace {
    static void printUsage(const char* program) {
        printf("usage: %s [--driver ICD.json] [output.png]\n", program);
    }

    static Options parseOptions(int argumentCount, char** arguments) {
        Options options{"vulkan.png", nullptr};
        bool haveOutput = false;
        for (int index = 1; index < argumentCount; ++index) {
            if (strcmp(arguments[index], "--help") == 0) {
                printUsage(arguments[0]);
                exit(0);
            }
            if (strcmp(arguments[index], "--driver") == 0) {
                if (++index == argumentCount) {
                    throw Error("--driver requires a Vulkan ICD manifest path");
                }
                options.driver = arguments[index];
            } else if (!haveOutput) {
                options.output = arguments[index];
                haveOutput = true;
            } else {
                throw Error("too many arguments");
            }
        }
        return options;
    }
}

int main(int argumentCount, char** arguments) {
    dlinit();
    try {
        Options options = parseOptions(argumentCount, arguments);
        if (options.driver != nullptr && setenv("VK_DRIVER_FILES", options.driver, 1) != 0) {
            throw Error("cannot set VK_DRIVER_FILES");
        }
        if (getenv("VK_LOADER_LAYERS_DISABLE") == nullptr) {
            setenv("VK_LOADER_LAYERS_DISABLE", "~implicit~", 0);
        }
        Renderer renderer;
        renderer.render(options.output);
        return 0;
    } catch (const Error& error) {
        fprintf(stderr, "vulkan: %s\n", error.message());
        return 1;
    } catch (...) {
        fprintf(stderr, "vulkan: unknown C++ exception\n");
        return 1;
    }
}
